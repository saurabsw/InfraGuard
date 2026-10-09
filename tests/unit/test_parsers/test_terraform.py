"""Unit tests for Terraform HCL parser adapter."""

from __future__ import annotations

from app.core.constants import Provider
from app.parsers.terraform import TerraformParser


class TestTerraformParser:
    def test_parse_valid_hcl(self):
        parser = TerraformParser()
        content = """
        resource "aws_s3_bucket" "test" {
          bucket = "my-test-bucket"
        }
        """
        result = parser.parse(content, "main.tf", Provider.AWS.value)
        assert result.success is True
        assert len(result.resources) == 1
        res = result.resources[0]
        assert res.resource_type == "aws_s3_bucket"
        assert res.resource_id == "test"
        assert res.properties.get("bucket") == "my-test-bucket"

    def test_parse_bytes_content(self):
        parser = TerraformParser()
        content = b'resource "aws_ebs_volume" "vol" { size = 10 }'
        result = parser.parse(content, "vol.tf", Provider.AWS.value)
        assert result.success is True
        assert len(result.resources) == 1

    def test_parse_malformed_syntax(self):
        parser = TerraformParser()
        content = 'resource "aws_s3_bucket" "broken" { unclosed'
        result = parser.parse(content, "broken.tf", Provider.AWS.value)
        assert result.success is False
        assert len(result.diagnostics) > 0
        assert result.diagnostics[0].severity == "error"

    def test_parse_invalid_utf8(self):
        parser = TerraformParser()
        content = b"\x80abc"
        result = parser.parse(content, "bad.tf", Provider.AWS.value)
        assert result.success is False
        assert "UTF-8" in result.diagnostics[0].message

    def test_module_warning(self):
        parser = TerraformParser()
        content = """
        module "vpc" {
          source = "terraform-aws-modules/vpc/aws"
        }
        """
        result = parser.parse(content, "mod.tf", Provider.AWS.value)
        assert "module" in result.unsupported_constructs
        assert any("module" in d.message.lower() for d in result.diagnostics)

    def test_supported_formats(self):
        parser = TerraformParser()
        assert "terraform" in parser.supported_formats()
