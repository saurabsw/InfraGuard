"""Report export schemas."""

from __future__ import annotations

from enum import StrEnum


class ReportFormat(StrEnum):
    """Supported report export formats."""

    JSON = "json"
    CSV = "csv"
