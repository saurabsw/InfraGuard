"""Unit tests for Resource Normalizer."""

from __future__ import annotations

from app.core.constants import ConfigFormat, EvaluationStatus, Provider
from app.normalization.normalizer import ResourceNormalizer
from app.parsers.base import ParsedResource


class TestResourceNormalizer:
    def test_normalize_aws_terraform_s3(self):
        norm = ResourceNormalizer()
        raw = [
            ParsedResource(
                resource_type="aws_s3_bucket",
                resource_id="my_bucket",
                properties={"bucket": "my-bucket"},
                source_file="main.tf",
            )
        ]
        results = norm.normalize(raw, Provider.AWS, ConfigFormat.TERRAFORM)
        assert len(results) == 1
        res = results[0]
        assert res.provider == Provider.AWS
        assert res.resource_type == "s3_bucket"
        assert res.resource_id == "my_bucket"
        assert res.evaluation_status == EvaluationStatus.NOT_EVALUATED

    def test_normalize_aws_cloudformation_sg(self):
        norm = ResourceNormalizer()
        raw = [
            ParsedResource(
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="MySG",
                properties={"GroupDescription": "test"},
                source_file="template.yaml",
            )
        ]
        results = norm.normalize(raw, Provider.AWS, ConfigFormat.CLOUDFORMATION)
        assert len(results) == 1
        res = results[0]
        assert res.provider == Provider.AWS
        assert res.resource_type == "security_group"
        assert res.resource_id == "MySG"

    def test_unsupported_resource_marked_unsupported(self):
        norm = ResourceNormalizer()
        raw = [
            ParsedResource(
                resource_type="aws_kinesis_firehose_delivery_stream",
                resource_id="stream",
                properties={"name": "test"},
                source_file="main.tf",
            )
        ]
        results = norm.normalize(raw, Provider.AWS, ConfigFormat.TERRAFORM)
        assert len(results) == 1
        res = results[0]
        assert res.evaluation_status == EvaluationStatus.UNSUPPORTED
        assert res.raw_type == "aws_kinesis_firehose_delivery_stream"
