"""Unit tests for parser registry."""

from __future__ import annotations

import pytest

from app.core.constants import ConfigFormat, Provider
from app.core.exceptions import UnsupportedFormatError
from app.parsers.cloudformation import CloudFormationParser
from app.parsers.registry import get_parser
from app.parsers.terraform import TerraformParser


class TestParserRegistry:
    def test_get_terraform_parser(self):
        for prov in [Provider.AWS, Provider.AZURE, Provider.GCP]:
            p = get_parser(prov, ConfigFormat.TERRAFORM)
            assert isinstance(p, TerraformParser)

    def test_get_cloudformation_parser_aws(self):
        p = get_parser(Provider.AWS, ConfigFormat.CLOUDFORMATION)
        assert isinstance(p, CloudFormationParser)

    def test_reject_cloudformation_for_azure(self):
        with pytest.raises(UnsupportedFormatError):
            get_parser(Provider.AZURE, ConfigFormat.CLOUDFORMATION)

    def test_reject_cloudformation_for_gcp(self):
        with pytest.raises(UnsupportedFormatError):
            get_parser(Provider.GCP, ConfigFormat.CLOUDFORMATION)
