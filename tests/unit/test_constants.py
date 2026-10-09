"""Unit tests for provider registry and constants."""

from __future__ import annotations

import pytest

from app.core.constants import (
    SEVERITY_PENALTIES,
    ConfigFormat,
    EvaluationStatus,
    Provider,
    RiskBand,
    Severity,
    get_all_providers,
    get_provider_info,
    is_valid_provider_format,
)


class TestProviderEnum:
    """Provider enum values match PRD §5 canonical identifiers."""

    def test_aws(self):
        assert Provider.AWS.value == "aws"

    def test_azure(self):
        assert Provider.AZURE.value == "azure"

    def test_gcp(self):
        assert Provider.GCP.value == "gcp"

    def test_exactly_three_providers(self):
        assert len(Provider) == 3


class TestConfigFormatEnum:
    def test_terraform(self):
        assert ConfigFormat.TERRAFORM.value == "terraform"

    def test_cloudformation(self):
        assert ConfigFormat.CLOUDFORMATION.value == "cloudformation"


class TestSeverityEnum:
    def test_all_severities_defined(self):
        assert set(Severity) == {
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        }


class TestEvaluationStatus:
    """PRD §7 evaluation statuses."""

    def test_pass(self):
        assert EvaluationStatus.PASS.value == "PASS"

    def test_fail(self):
        assert EvaluationStatus.FAIL.value == "FAIL"

    def test_not_evaluated(self):
        assert EvaluationStatus.NOT_EVALUATED.value == "NOT_EVALUATED"

    def test_unsupported(self):
        assert EvaluationStatus.UNSUPPORTED.value == "UNSUPPORTED"

    def test_exactly_four_statuses(self):
        assert len(EvaluationStatus) == 4


class TestRiskBand:
    def test_all_bands(self):
        assert set(RiskBand) == {
            RiskBand.LOW,
            RiskBand.MODERATE,
            RiskBand.HIGH,
            RiskBand.CRITICAL,
        }


class TestSeverityPenalties:
    """PRD §8 penalty points."""

    def test_critical(self):
        assert SEVERITY_PENALTIES[Severity.CRITICAL] == 25

    def test_high(self):
        assert SEVERITY_PENALTIES[Severity.HIGH] == 15

    def test_medium(self):
        assert SEVERITY_PENALTIES[Severity.MEDIUM] == 7

    def test_low(self):
        assert SEVERITY_PENALTIES[Severity.LOW] == 3

    def test_all_severities_have_penalties(self):
        for sev in Severity:
            assert sev in SEVERITY_PENALTIES


class TestProviderRegistry:
    """Provider registry correctness — PRD §5."""

    def test_get_all_returns_three(self):
        providers = get_all_providers()
        assert len(providers) == 3

    def test_aws_provider_info(self):
        info = get_provider_info(Provider.AWS)
        assert info.provider_id == Provider.AWS
        assert info.name == "Amazon Web Services"
        format_ids = [f.format_id for f in info.supported_formats]
        assert ConfigFormat.TERRAFORM in format_ids
        assert ConfigFormat.CLOUDFORMATION in format_ids

    def test_azure_provider_info(self):
        info = get_provider_info(Provider.AZURE)
        assert info.provider_id == Provider.AZURE
        assert info.name == "Microsoft Azure"
        format_ids = [f.format_id for f in info.supported_formats]
        assert ConfigFormat.TERRAFORM in format_ids
        assert ConfigFormat.CLOUDFORMATION not in format_ids

    def test_gcp_provider_info(self):
        info = get_provider_info(Provider.GCP)
        assert info.provider_id == Provider.GCP
        assert info.name == "Google Cloud Platform"
        format_ids = [f.format_id for f in info.supported_formats]
        assert ConfigFormat.TERRAFORM in format_ids
        assert ConfigFormat.CLOUDFORMATION not in format_ids

    def test_aws_terraform_extensions(self):
        info = get_provider_info(Provider.AWS)
        exts = info.get_allowed_extensions()
        assert ".tf" in exts

    def test_aws_cloudformation_extensions(self):
        info = get_provider_info(Provider.AWS)
        exts = info.get_allowed_extensions()
        assert ".yaml" in exts
        assert ".yml" in exts
        assert ".json" in exts

    def test_provider_info_to_dict(self):
        info = get_provider_info(Provider.AWS)
        d = info.to_dict()
        assert d["id"] == "aws"
        assert d["name"] == "Amazon Web Services"
        assert isinstance(d["supported_formats"], list)
        assert len(d["supported_formats"]) == 2

    def test_format_info_to_dict(self):
        info = get_provider_info(Provider.AWS)
        tf = info.supported_formats[0]
        d = tf.to_dict()
        assert d["id"] == "terraform"
        assert d["name"] == "Terraform HCL"
        assert d["extensions"] == [".tf"]


class TestProviderFormatValidation:
    """is_valid_provider_format function."""

    @pytest.mark.parametrize(
        ("provider", "fmt", "expected"),
        [
            (Provider.AWS, ConfigFormat.TERRAFORM, True),
            (Provider.AWS, ConfigFormat.CLOUDFORMATION, True),
            (Provider.AZURE, ConfigFormat.TERRAFORM, True),
            (Provider.AZURE, ConfigFormat.CLOUDFORMATION, False),
            (Provider.GCP, ConfigFormat.TERRAFORM, True),
            (Provider.GCP, ConfigFormat.CLOUDFORMATION, False),
        ],
    )
    def test_valid_combinations(self, provider, fmt, expected):
        assert is_valid_provider_format(provider, fmt) is expected
