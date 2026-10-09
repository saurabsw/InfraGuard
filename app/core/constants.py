"""Shared constants, enumerations, and provider/format definitions.

This module is the single source of truth for supported providers,
formats, severities, evaluation statuses, and upload constraints.
"""

from __future__ import annotations

from enum import StrEnum

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Provider(StrEnum):
    """Supported cloud providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class ConfigFormat(StrEnum):
    """Supported IaC configuration formats."""

    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"


class Severity(StrEnum):
    """Finding severity levels with penalty points."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvaluationStatus(StrEnum):
    """Evaluation outcome for a finding."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_EVALUATED = "NOT_EVALUATED"
    UNSUPPORTED = "UNSUPPORTED"


class ScanStatus(StrEnum):
    """Overall scan status."""

    COMPLETED = "completed"
    FAILED = "failed"


class RiskBand(StrEnum):
    """Risk score band classification."""

    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Severity penalty points (PRD §8)
# ---------------------------------------------------------------------------

SEVERITY_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
}


# ---------------------------------------------------------------------------
# Provider → Format compatibility (PRD §5)
# ---------------------------------------------------------------------------


class FormatInfo:
    """Metadata for a supported configuration format."""

    def __init__(self, format_id: ConfigFormat, name: str, extensions: list[str]):
        self.format_id = format_id
        self.name = name
        self.extensions = extensions

    def to_dict(self) -> dict:
        return {
            "id": self.format_id.value,
            "name": self.name,
            "extensions": self.extensions,
        }


class ProviderInfo:
    """Metadata for a supported cloud provider."""

    def __init__(
        self,
        provider_id: Provider,
        name: str,
        supported_formats: list[FormatInfo],
    ):
        self.provider_id = provider_id
        self.name = name
        self.supported_formats = supported_formats

    def supports_format(self, fmt: ConfigFormat) -> bool:
        return any(f.format_id == fmt for f in self.supported_formats)

    def get_allowed_extensions(self) -> set[str]:
        exts: set[str] = set()
        for f in self.supported_formats:
            exts.update(f.extensions)
        return exts

    def to_dict(self) -> dict:
        return {
            "id": self.provider_id.value,
            "name": self.name,
            "supported_formats": [f.to_dict() for f in self.supported_formats],
        }


# ---------------------------------------------------------------------------
# Provider registry — single source of truth
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY: dict[Provider, ProviderInfo] = {
    Provider.AWS: ProviderInfo(
        provider_id=Provider.AWS,
        name="Amazon Web Services",
        supported_formats=[
            FormatInfo(
                format_id=ConfigFormat.TERRAFORM,
                name="Terraform HCL",
                extensions=[".tf"],
            ),
            FormatInfo(
                format_id=ConfigFormat.CLOUDFORMATION,
                name="CloudFormation",
                extensions=[".yaml", ".yml", ".json"],
            ),
        ],
    ),
    Provider.AZURE: ProviderInfo(
        provider_id=Provider.AZURE,
        name="Microsoft Azure",
        supported_formats=[
            FormatInfo(
                format_id=ConfigFormat.TERRAFORM,
                name="Terraform HCL",
                extensions=[".tf"],
            ),
        ],
    ),
    Provider.GCP: ProviderInfo(
        provider_id=Provider.GCP,
        name="Google Cloud Platform",
        supported_formats=[
            FormatInfo(
                format_id=ConfigFormat.TERRAFORM,
                name="Terraform HCL",
                extensions=[".tf"],
            ),
        ],
    ),
}


def get_provider_info(provider: Provider) -> ProviderInfo:
    """Get provider info or raise KeyError."""
    return PROVIDER_REGISTRY[provider]


def is_valid_provider_format(provider: Provider, fmt: ConfigFormat) -> bool:
    """Check if a provider supports a given format."""
    info = PROVIDER_REGISTRY.get(provider)
    if info is None:
        return False
    return info.supports_format(fmt)


def get_all_providers() -> list[ProviderInfo]:
    """Return all registered providers."""
    return list(PROVIDER_REGISTRY.values())
