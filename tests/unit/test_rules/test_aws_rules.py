"""Unit tests for AWS security rules (IG-AWS-001 to IG-AWS-010, IG-IAM-001).

Tests positive (FAIL on insecure), negative (PASS on secure),
edge cases (NOT_EVALUATED), and unsupported resource types.
"""

from __future__ import annotations

import json

from app.core.constants import EvaluationStatus, Provider
from app.rules.aws import (
    EBSVolumeEncryptionRule,
    IAMWildcardPermissionsRule,
    RDSPublicAccessRule,
    RDSStorageEncryptionRule,
    S3BlockPublicAccessRule,
    S3BucketLoggingRule,
    S3PublicReadRule,
    S3PublicWriteRule,
    SecurityGroupPermissiveRule,
    SecurityGroupRDPRule,
    SecurityGroupSSHRule,
)
from app.schemas.resource import NormalizedResource


def _make_res(res_type: str, props: dict, res_id: str = "test") -> NormalizedResource:
    return NormalizedResource(
        provider=Provider.AWS,
        resource_type=res_type,
        resource_id=res_id,
        source_file="test.tf",
        properties=props,
    )


class TestS3PublicReadRule:
    rule = S3PublicReadRule()

    def test_fail_on_public_read(self):
        policy = json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}
        )
        res = _make_res("s3_bucket_policy", {"policy": policy})
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.FAIL

    def test_pass_on_restricted(self):
        policy = json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123:root"},
                        "Action": "s3:GetObject",
                    }
                ]
            }
        )
        res = _make_res("s3_bucket_policy", {"policy": policy})
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.PASS

    def test_not_evaluated_on_empty(self):
        res = _make_res("s3_bucket_policy", {})
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.NOT_EVALUATED

    def test_unsupported_resource_type(self):
        res = _make_res("security_group", {})
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.UNSUPPORTED


class TestS3PublicWriteRule:
    rule = S3PublicWriteRule()

    def test_fail_on_public_write(self):
        policy = json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:PutObject"]}]}
        )
        res = _make_res("s3_bucket_policy", {"policy": policy})
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.FAIL

    def test_pass_on_read_only(self):
        policy = json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["s3:GetObject"]}]}
        )
        res = _make_res("s3_bucket_policy", {"policy": policy})
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.PASS


class TestS3BlockPublicAccessRule:
    rule = S3BlockPublicAccessRule()

    def test_pass_when_all_true(self):
        props = {
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        }
        res = _make_res("s3_public_access_block", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.PASS

    def test_fail_when_one_false(self):
        props = {
            "block_public_acls": True,
            "block_public_policy": False,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        }
        res = _make_res("s3_public_access_block", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.FAIL


class TestSecurityGroupSSHRule:
    rule = SecurityGroupSSHRule()

    def test_fail_on_open_ssh(self):
        props = {
            "ingress": [
                {"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"], "protocol": "tcp"}
            ]
        }
        res = _make_res("security_group", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.FAIL

    def test_pass_on_restricted_ssh(self):
        props = {
            "ingress": [
                {"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/16"], "protocol": "tcp"}
            ]
        }
        res = _make_res("security_group", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.PASS


class TestSecurityGroupRDPRule:
    rule = SecurityGroupRDPRule()

    def test_fail_on_open_rdp(self):
        props = {
            "ingress": [
                {
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "protocol": "tcp",
                }
            ]
        }
        res = _make_res("security_group", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.FAIL

    def test_pass_on_restricted_rdp(self):
        props = {
            "ingress": [
                {
                    "from_port": 3389,
                    "to_port": 3389,
                    "cidr_blocks": ["10.0.0.0/8"],
                    "protocol": "tcp",
                }
            ]
        }
        res = _make_res("security_group", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.PASS


class TestSecurityGroupPermissiveRule:
    rule = SecurityGroupPermissiveRule()

    def test_fail_on_wildcard_protocol(self):
        props = {
            "ingress": [
                {"from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"], "protocol": "-1"}
            ]
        }
        res = _make_res("security_group", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.FAIL

    def test_pass_on_explicit_port(self):
        props = {
            "ingress": [
                {"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"], "protocol": "tcp"}
            ]
        }
        res = _make_res("security_group", props)
        result = self.rule.evaluate(res)
        assert result.status == EvaluationStatus.PASS


class TestRDSPublicAccessRule:
    rule = RDSPublicAccessRule()

    def test_fail_when_public(self):
        res = _make_res("rds_instance", {"publicly_accessible": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_private(self):
        res = _make_res("rds_instance", {"publicly_accessible": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestRDSStorageEncryptionRule:
    rule = RDSStorageEncryptionRule()

    def test_fail_when_false(self):
        res = _make_res("rds_instance", {"storage_encrypted": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_true(self):
        res = _make_res("rds_instance", {"storage_encrypted": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS

    def test_not_evaluated_when_omitted(self):
        res = _make_res("rds_instance", {})
        assert self.rule.evaluate(res).status == EvaluationStatus.NOT_EVALUATED


class TestEBSVolumeEncryptionRule:
    rule = EBSVolumeEncryptionRule()

    def test_fail_when_false(self):
        res = _make_res("ebs_volume", {"encrypted": False})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_true(self):
        res = _make_res("ebs_volume", {"encrypted": True})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS

    def test_not_evaluated_when_omitted(self):
        res = _make_res("ebs_volume", {})
        assert self.rule.evaluate(res).status == EvaluationStatus.NOT_EVALUATED


class TestIAMWildcardPermissionsRule:
    rule = IAMWildcardPermissionsRule()

    def test_fail_on_wildcard_admin(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        res = _make_res("iam_policy", {"policy": json.dumps(policy)})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_on_scoped(self):
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-b/*"}
            ]
        }
        res = _make_res("iam_policy", {"policy": json.dumps(policy)})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS


class TestS3BucketLoggingRule:
    rule = S3BucketLoggingRule()

    def test_fail_when_missing_logging(self):
        res = _make_res("s3_bucket", {"bucket": "b"})
        assert self.rule.evaluate(res).status == EvaluationStatus.FAIL

    def test_pass_when_logging_configured(self):
        res = _make_res("s3_bucket", {"bucket": "b", "logging": {"target_bucket": "logs"}})
        assert self.rule.evaluate(res).status == EvaluationStatus.PASS
