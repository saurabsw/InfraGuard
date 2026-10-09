"""Base parser adapter definitions and diagnostic structures.

All parsers must implement ParserAdapter. Parsers must NEVER execute
user code or run external binaries (PRD §5, §6).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ParsedResource:
    """A single raw resource parsed from configuration code."""

    resource_type: str
    resource_id: str
    properties: dict[str, Any]
    source_file: str
    source_location: str | None = None


@dataclass
class ParseDiagnostic:
    """Diagnostic message generated during parsing (warning or error)."""

    file: str
    message: str
    severity: str  # "error" | "warning"
    line: int | None = None


@dataclass
class ParseResult:
    """The aggregate output of a parsing operation."""

    resources: list[ParsedResource] = field(default_factory=list)
    diagnostics: list[ParseDiagnostic] = field(default_factory=list)
    format_detected: str = ""
    success: bool = True
    unsupported_constructs: list[str] = field(default_factory=list)


class ParserAdapter(ABC):
    """Abstract interface for configuration format parsers."""

    @abstractmethod
    def supported_formats(self) -> list[str]:
        """List of format identifiers supported by this adapter."""
        ...

    @abstractmethod
    def parse(
        self,
        content: str | bytes,
        filename: str,
        provider: str,
    ) -> ParseResult:
        """Parse configuration content into structured resources.

        MUST NOT execute commands or external processes.
        MUST NOT silently discard malformed syntax.
        """
        ...
