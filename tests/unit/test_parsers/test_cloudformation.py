"""Unit tests for CloudFormation parser adapter."""

from __future__ import annotations

from app.core.constants import Provider
from app.parsers.cloudformation import CloudFormationParser


class TestCloudFormationParser:
    def test_parse_valid_yaml(self):
        parser = CloudFormationParser()
        content = """
        AWSTemplateFormatVersion: '2010-09-09'
        Resources:
          MyBucket:
            Type: AWS::S3::Bucket
            Properties:
              BucketName: my-cf-bucket
        """
        result = parser.parse(content, "template.yaml", Provider.AWS.value)
        assert result.success is True
        assert len(result.resources) == 1
        res = result.resources[0]
        assert res.resource_type == "AWS::S3::Bucket"
        assert res.resource_id == "MyBucket"
        assert res.properties.get("BucketName") == "my-cf-bucket"

    def test_parse_valid_json(self):
        parser = CloudFormationParser()
        content = """{
          "Resources": {
            "MySG": {
              "Type": "AWS::EC2::SecurityGroup",
              "Properties": {
                "GroupDescription": "Test SG"
              }
            }
          }
        }"""
        result = parser.parse(content, "template.json", Provider.AWS.value)
        assert result.success is True
        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "AWS::EC2::SecurityGroup"

    def test_intrinsic_tags_supported(self):
        parser = CloudFormationParser()
        content = """
        Resources:
          Subnet:
            Type: AWS::EC2::Subnet
            Properties:
              VpcId: !Ref MyVPC
        """
        result = parser.parse(content, "tags.yaml", Provider.AWS.value)
        assert result.success is True
        assert len(result.resources) == 1
        assert "Fn::Ref" in result.resources[0].properties.get("VpcId", {})

    def test_reject_non_aws_provider(self):
        parser = CloudFormationParser()
        content = "Resources: {}"
        result = parser.parse(content, "test.yaml", Provider.AZURE.value)
        assert result.success is False
        assert any("not supported for provider 'azure'" in d.message for d in result.diagnostics)

    def test_malformed_yaml(self):
        parser = CloudFormationParser()
        content = "Resources: [bad: yaml"
        result = parser.parse(content, "bad.yaml", Provider.AWS.value)
        assert result.success is False
        assert any(d.severity == "error" for d in result.diagnostics)

    def test_missing_resources_warning(self):
        parser = CloudFormationParser()
        content = "AWSTemplateFormatVersion: '2010-09-09'\nMetadata: {}"
        result = parser.parse(content, "empty.yaml", Provider.AWS.value)
        assert result.success is True
        assert len(result.resources) == 0
        assert any("no valid 'resources' block" in d.message.lower() for d in result.diagnostics)
