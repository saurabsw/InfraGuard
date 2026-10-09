"""Unit tests for Azure security rules (IG-AZ-001 to IG-AZ-007)."""

from __future__ import annotations

from app.core.constants import EvaluationStatus, Provider
from app.rules.azure import (
    DatabasePublicAccessRule,
    NSGOverlyPermissiveRule,
    NSGRDPRule,
    NSGSSHRule,
    StorageInfrastructureEncryptionRule,
    StoragePublicBlobRule,
    StorageSecureTransferRule,
)
from app.schemas.resource import NormalizedResource


def _make_az_res(res_type: str, props: dict, res_id: str = "az_test") -> NormalizedResource:
    return NormalizedResource(
        provider=Provider.AZURE,
        resource_type=res_type,
        resource_id=res_id,
        source_file="az.tf",
        properties=props,
    )


class TestStoragePublicBlobRule:
    rule = StoragePublicBlobRule()

    def test_fail_when_allowed(self):
        res = _make_az_res("storage_account", {"allow_nested_items_to_be_public": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_disabled(self):
        res = _make_az_res("storage_account", {"allow_nested_items_to_be_public": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS

    def test_not_evaluated_when_omitted(self):
        res = _make_az_res("storage_account", {})
        assert self.rule.evaluate(res).status == EvaluationStatus.NOT_EVALUATED


class TestNSGSSHRule:
    rule = NSGSSHRule()

    def test_fail_when_ssh_open_to_internet(self):
        props = {
            "security_rule": [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "destination_port_range": "22",
                    "source_address_prefix": "Internet",
                }
            ]
        }
        res = _make_az_res("network_security_group", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_ssh_restricted(self):
        props = {
            "security_rule": [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "destination_port_range": "22",
                    "source_address_prefix": "10.0.0.1",
                }
            ]
        }
        res = _make_az_res("network_security_group", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestNSGRDPRule:
    rule = NSGRDPRule()

    def test_fail_when_rdp_open_to_wildcard(self):
        props = {
            "security_rule": [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "destination_port_range": "3389",
                    "source_address_prefix": "*",
                }
            ]
        }
        res = _make_az_res("network_security_group", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL


class TestStorageSecureTransferRule:
    rule = StorageSecureTransferRule()

    def test_fail_when_disabled(self):
        res = _make_az_res("storage_account", {"enable_https_traffic_only": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_enabled(self):
        res = _make_az_res("storage_account", {"enable_https_traffic_only": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestStorageInfrastructureEncryptionRule:
    rule = StorageInfrastructureEncryptionRule()

    def test_fail_when_missing(self):
        res = _make_az_res("storage_account", {})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_enabled(self):
        res = _make_az_res("storage_account", {"infrastructure_encryption_enabled": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestNSGOverlyPermissiveRule:
    rule = NSGOverlyPermissiveRule()

    def test_fail_when_wildcard_all(self):
        props = {
            "security_rule": [
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "*",
                    "destination_port_range": "*",
                    "source_address_prefix": "*",
                }
            ]
        }
        res = _make_az_res("network_security_group", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL


class TestDatabasePublicAccessRule:
    rule = DatabasePublicAccessRule()

    def test_fail_when_public(self):
        res = _make_az_res("sql_server", {"public_network_access_enabled": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_private(self):
        res = _make_az_res("sql_server", {"public_network_access_enabled": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS
