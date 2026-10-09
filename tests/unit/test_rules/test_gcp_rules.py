"""Unit tests for GCP security rules (IG-GCP-001 to IG-GCP-007)."""

from __future__ import annotations

from app.core.constants import EvaluationStatus, Provider
from app.rules.gcp import (
    FirewallPermissiveRule,
    FirewallRDPRule,
    FirewallSSHRule,
    ProjectIAMBroadGrantsRule,
    StoragePublicAccessPreventionRule,
    StoragePublicIAMRule,
    StorageUniformAccessRule,
)
from app.schemas.resource import NormalizedResource


def _make_gcp_res(res_type: str, props: dict, res_id: str = "gcp_test") -> NormalizedResource:
    return NormalizedResource(
        provider=Provider.GCP,
        resource_type=res_type,
        resource_id=res_id,
        source_file="gcp.tf",
        properties=props,
    )


class TestStoragePublicIAMRule:
    rule = StoragePublicIAMRule()

    def test_fail_when_all_users(self):
        res = _make_gcp_res("storage_iam_binding", {"members": ["allUsers"]})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_specific_user(self):
        res = _make_gcp_res("storage_iam_binding", {"members": ["user:alice@example.com"]})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestFirewallSSHRule:
    rule = FirewallSSHRule()

    def test_fail_when_ssh_open(self):
        props = {
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        }
        res = _make_gcp_res("firewall_rule", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_ssh_restricted(self):
        props = {
            "source_ranges": ["10.0.0.0/16"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
        }
        res = _make_gcp_res("firewall_rule", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestFirewallRDPRule:
    rule = FirewallRDPRule()

    def test_fail_when_rdp_open(self):
        props = {
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "tcp", "ports": ["3389"]}],
        }
        res = _make_gcp_res("firewall_rule", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL


class TestFirewallPermissiveRule:
    rule = FirewallPermissiveRule()

    def test_fail_when_allow_all(self):
        props = {
            "source_ranges": ["0.0.0.0/0"],
            "allow": [{"protocol": "all"}],
        }
        res = _make_gcp_res("firewall_rule", props)
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL


class TestStorageUniformAccessRule:
    rule = StorageUniformAccessRule()

    def test_fail_when_false(self):
        res = _make_gcp_res("storage_bucket", {"uniform_bucket_level_access": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_true(self):
        res = _make_gcp_res("storage_bucket", {"uniform_bucket_level_access": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestStoragePublicAccessPreventionRule:
    rule = StoragePublicAccessPreventionRule()

    def test_fail_when_inherited(self):
        res = _make_gcp_res("storage_bucket", {"public_access_prevention": "inherited"})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_enforced(self):
        res = _make_gcp_res("storage_bucket", {"public_access_prevention": "enforced"})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestProjectIAMBroadGrantsRule:
    rule = ProjectIAMBroadGrantsRule()

    def test_fail_when_owner_to_public(self):
        res = _make_gcp_res(
            "project_iam_binding",
            {"role": "roles/owner", "members": ["allUsers"]},
        )
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_scoped(self):
        res = _make_gcp_res(
            "project_iam_binding",
            {"role": "roles/viewer", "members": ["group:devs@example.com"]},
        )
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS
