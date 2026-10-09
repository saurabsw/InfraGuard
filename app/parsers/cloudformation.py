"""CloudFormation parser adapter.

Safely parses AWS CloudFormation YAML and JSON templates without executing code.
Supports standard intrinsic function tags (!Ref, !Sub, !GetAtt, etc.).
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from app.core.constants import ConfigFormat, Provider
from app.parsers.base import (
    ParseDiagnostic,
    ParsedResource,
    ParserAdapter,
    ParseResult,
)


class CloudFormationSafeLoader(yaml.SafeLoader):
    """Custom YAML loader that safely handles CloudFormation intrinsic tags."""


def _cfn_tag_constructor(loader: yaml.SafeLoader, tag_suffix: str, node: yaml.Node) -> Any:
    """Constructor for CloudFormation short-form tags like !Ref, !Sub."""
    if isinstance(node, yaml.ScalarNode):
        return {f"Fn::{tag_suffix}": loader.construct_scalar(node)}
    elif isinstance(node, yaml.SequenceNode):
        return {f"Fn::{tag_suffix}": loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {f"Fn::{tag_suffix}": loader.construct_mapping(node)}
    return None


# Register multi-constructor for all short tags
CloudFormationSafeLoader.add_multi_constructor("!", _cfn_tag_constructor)


class CloudFormationParser(ParserAdapter):
    """Adapter for parsing CloudFormation YAML or JSON templates."""

    def supported_formats(self) -> list[str]:
        return [ConfigFormat.CLOUDFORMATION.value]

    def parse(
        self,
        content: str | bytes,
        filename: str,
        provider: str,
    ) -> ParseResult:
        result = ParseResult(
            format_detected=ConfigFormat.CLOUDFORMATION.value,
            success=True,
        )

        if provider != Provider.AWS.value:
            result.diagnostics.append(
                ParseDiagnostic(
                    file=filename,
                    message=f"CloudFormation format is not supported for provider '{provider}'",
                    severity="error",
                )
            )
            result.success = False
            return result

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

        parsed_data: dict[str, Any] | None = None

        # Attempt parsing as JSON or YAML
        is_json = filename.lower().endswith(".json") or text_content.strip().startswith("{")
        if is_json:
            try:
                parsed_data = json.loads(text_content)
            except json.JSONDecodeError as j_exc:
                if filename.lower().endswith(".json"):
                    result.diagnostics.append(
                        ParseDiagnostic(
                            file=filename,
                            message=f"JSON syntax error: {j_exc}",
                            severity="error",
                            line=j_exc.lineno,
                        )
                    )
                    result.success = False
                    return result

        if parsed_data is None:
            try:
                parsed_data = yaml.load(text_content, Loader=CloudFormationSafeLoader)
            except Exception as y_exc:
                line_no = None
                if hasattr(y_exc, "problem_mark") and y_exc.problem_mark:
                    line_no = y_exc.problem_mark.line + 1
                result.diagnostics.append(
                    ParseDiagnostic(
                        file=filename,
                        message=f"YAML syntax error: {y_exc}",
                        severity="error",
                        line=line_no,
                    )
                )
                result.success = False
                return result

        if not isinstance(parsed_data, dict):
            result.diagnostics.append(
                ParseDiagnostic(
                    file=filename,
                    message="CloudFormation template root must be a dictionary/mapping",
                    severity="error",
                )
            )
            result.success = False
            return result

        raw_resources = parsed_data.get("Resources")
        if not raw_resources or not isinstance(raw_resources, dict):
            result.diagnostics.append(
                ParseDiagnostic(
                    file=filename,
                    message="CloudFormation template contains no valid 'Resources' block",
                    severity="warning",
                )
            )
            return result

        for r_name, r_body in raw_resources.items():
            if not isinstance(r_body, dict):
                continue
            r_type = r_body.get("Type")
            if not r_type or not isinstance(r_type, str):
                continue
            r_props = r_body.get("Properties", {})
            if not isinstance(r_props, dict):
                r_props = {}

            result.resources.append(
                ParsedResource(
                    resource_type=r_type,
                    resource_id=str(r_name),
                    properties=r_props,
                    source_file=filename,
                    source_location=None,
                )
            )

        return result
