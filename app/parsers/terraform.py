"""Terraform HCL parser adapter.

Uses python-hcl2 to statically parse HCL files into raw resource definitions.
Never executes terraform CLI, shell commands, or external binaries.
"""

from __future__ import annotations

import io
from typing import Any

import hcl2

from app.core.constants import ConfigFormat
from app.parsers.base import (
    ParseDiagnostic,
    ParsedResource,
    ParserAdapter,
    ParseResult,
)


class TerraformParser(ParserAdapter):
    """Adapter for parsing Terraform HCL (.tf) files."""

    def supported_formats(self) -> list[str]:
        return [ConfigFormat.TERRAFORM.value]

    def parse(
        self,
        content: str | bytes,
        filename: str,
        provider: str,
    ) -> ParseResult:
        result = ParseResult(
            format_detected=ConfigFormat.TERRAFORM.value,
            success=True,
        )

        text_content: str
        if isinstance(content, bytes):
            try:
                text_content = content.decode("utf-8")
            except UnicodeDecodeError as exc:
                result.diagnostics.append(
                    ParseDiagnostic(
                        file=filename,
                        message=f"File is not valid UTF-8: {exc}",
                        severity="error",
                    )
                )
                result.success = False
                return result
        else:
            text_content = content

        try:
            parsed_data: dict[str, Any] = hcl2.load(io.StringIO(text_content))
        except Exception as exc:  # LarkError or syntax parsing failure
            line_no = getattr(exc, "line", None)
            result.diagnostics.append(
                ParseDiagnostic(
                    file=filename,
                    message=f"HCL parsing error: {exc}",
                    severity="error",
                    line=line_no,
                )
            )
            result.success = False
            return result

        # Check for unsupported constructs
        if "module" in parsed_data:
            result.unsupported_constructs.append("module")
            result.diagnostics.append(
                ParseDiagnostic(
                    file=filename,
                    message="Terraform modules are not expanded in static MVP analysis",
                    severity="warning",
                )
            )

        # Parse resource blocks
        raw_resources = parsed_data.get("resource", [])
        for res_entry in raw_resources:
            if not isinstance(res_entry, dict):
                continue
            for r_type, r_instances in res_entry.items():
                if not isinstance(r_instances, dict):
                    continue
                clean_type = str(r_type).strip("\"'")
                for r_name, r_props in r_instances.items():
                    clean_id = str(r_name).strip("\"'")
                    props = r_props if isinstance(r_props, dict) else {"_raw": r_props}
                    cleaned_props = _clean_hcl_props(props)
                    result.resources.append(
                        ParsedResource(
                            resource_type=clean_type,
                            resource_id=clean_id,
                            properties=cleaned_props,
                            source_file=filename,
                            source_location=None,
                        )
                    )

        # Parse data blocks (e.g. data "aws_iam_policy_document" "name" {...})
        raw_data_blocks = parsed_data.get("data", [])
        for data_entry in raw_data_blocks:
            if not isinstance(data_entry, dict):
                continue
            for d_type, d_instances in data_entry.items():
                if not isinstance(d_instances, dict):
                    continue
                clean_dtype = str(d_type).strip("\"'")
                for d_name, d_props in d_instances.items():
                    clean_did = str(d_name).strip("\"'")
                    props = d_props if isinstance(d_props, dict) else {"_raw": d_props}
                    cleaned_props = _clean_hcl_props(props)
                    result.resources.append(
                        ParsedResource(
                            resource_type=f"data.{clean_dtype}",
                            resource_id=clean_did,
                            properties=cleaned_props,
                            source_file=filename,
                            source_location=None,
                        )
                    )

        return result


def _clean_hcl_props(val: Any) -> Any:
    """Recursively clean HCL dictionary properties."""
    if isinstance(val, dict):
        out = {}
        for k, v in val.items():
            if k == "__is_block__":
                continue
            clean_k = str(k).strip("\"'")
            out[clean_k] = _clean_hcl_props(v)
        return out
    elif isinstance(val, list):
        return [_clean_hcl_props(item) for item in val]
    elif isinstance(val, str):
        s = val.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
            return s[1:-1]
        return val
    return val
