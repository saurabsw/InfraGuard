"""Registry for configuration format parsers."""

from __future__ import annotations

from app.core.constants import ConfigFormat, Provider
from app.core.exceptions import UnsupportedFormatError
from app.parsers.base import ParserAdapter
from app.parsers.cloudformation import CloudFormationParser
from app.parsers.terraform import TerraformParser

_PARSER_REGISTRY: dict[ConfigFormat, ParserAdapter] = {
    ConfigFormat.TERRAFORM: TerraformParser(),
    ConfigFormat.CLOUDFORMATION: CloudFormationParser(),
}


def get_parser(provider: str | Provider, fmt: str | ConfigFormat) -> ParserAdapter:
    """Get the appropriate parser adapter for a provider and format.

    Raises UnsupportedFormatError if format is not supported.
    """
    prov_enum = Provider(provider) if isinstance(provider, str) else provider
    fmt_enum = ConfigFormat(fmt) if isinstance(fmt, str) else fmt

    # Validate provider + format compatibility
    if fmt_enum == ConfigFormat.CLOUDFORMATION and prov_enum != Provider.AWS:
        raise UnsupportedFormatError(provider=str(prov_enum.value), fmt=str(fmt_enum.value))

    adapter = _PARSER_REGISTRY.get(fmt_enum)
    if adapter is None:
        raise UnsupportedFormatError(provider=str(prov_enum.value), fmt=str(fmt_enum.value))

    return adapter
