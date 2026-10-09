"""Resource normalization service.

Maps parsed resources from provider-specific formats (Terraform, CloudFormation)
into canonical NormalizedResource models. Unrecognized resources are marked
as UNSUPPORTED, never silently dropped or marked PASS.
"""

from __future__ import annotations

from typing import Any

from app.core.constants import ConfigFormat, EvaluationStatus, Provider
from app.core.redaction import redact_dict
from app.normalization.cloudformation_map import get_cloudformation_canonical_type
from app.normalization.terraform_map import get_terraform_canonical_type
from app.parsers.base import ParsedResource
from app.schemas.resource import NormalizedResource


class ResourceNormalizer:
    """Normalizes raw parsed resources into canonical NormalizedResource instances."""

    def normalize(
        self,
        parsed_resources: list[ParsedResource],
        provider: Provider,
        config_format: ConfigFormat,
    ) -> list[NormalizedResource]:
        normalized: list[NormalizedResource] = []

        for item in parsed_resources:
            norm_res = self._normalize_single(item, provider, config_format)
            normalized.append(norm_res)

        return normalized

    def _normalize_single(
        self,
        item: ParsedResource,
        target_provider: Provider,
        config_format: ConfigFormat,
    ) -> NormalizedResource:
        canonical_info: tuple[Provider, str] | None = None

        if config_format == ConfigFormat.TERRAFORM:
            canonical_info = get_terraform_canonical_type(item.resource_type)
        elif config_format == ConfigFormat.CLOUDFORMATION:
            canonical_info = get_cloudformation_canonical_type(item.resource_type)

        if canonical_info is not None:
            res_provider, canonical_type = canonical_info
            # Check if mapped provider matches selected target provider
            if res_provider == target_provider:
                clean_props = self._clean_properties(item.properties)
                return NormalizedResource(
                    provider=res_provider,
                    resource_type=canonical_type,
                    resource_id=item.resource_id,
                    source_file=item.source_file,
                    source_location=item.source_location,
                    properties=clean_props,
                    raw_type=item.resource_type,
                    evaluation_status=EvaluationStatus.NOT_EVALUATED,
                )

        # Resource is outside supported scope for this provider/format
        return NormalizedResource(
            provider=target_provider,
            resource_type=item.resource_type,
            resource_id=item.resource_id,
            source_file=item.source_file,
            source_location=item.source_location,
            properties=self._clean_properties(item.properties),
            raw_type=item.resource_type,
            evaluation_status=EvaluationStatus.UNSUPPORTED,
        )

    def _clean_properties(self, props: dict[str, Any]) -> dict[str, Any]:
        """Normalize property values (e.g. unwrap single-element lists from HCL2) and redact secrets."""
        cleaned: dict[str, Any] = {}
        for k, v in props.items():
            cleaned[k] = self._clean_value(v)
        return redact_dict(cleaned)

    def _clean_value(self, val: Any) -> Any:
        if isinstance(val, dict):
            return {k: self._clean_value(v) for k, v in val.items()}
        elif isinstance(val, list):
            # If list contains dicts, clean each
            return [self._clean_value(item) for item in val]
        return val
