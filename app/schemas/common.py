"""Common Pydantic schemas shared across API endpoints.

Re-exports enumerations from core.constants to keep API schemas
self-contained and importable without touching internal modules.
"""

from __future__ import annotations

from pydantic import BaseModel

from app.core.constants import (
    ConfigFormat,
    EvaluationStatus,
    Provider,
    RiskBand,
    ScanStatus,
    Severity,
)

__all__ = [
    "ConfigFormat",
    "EvaluationStatus",
    "Provider",
    "RiskBand",
    "ScanStatus",
    "Severity",
    "ErrorResponse",
]


class ErrorResponse(BaseModel):
    """Structured error response returned to API clients.

    Never contains stack traces or internal details (PRD §13).
    """

    error: str
    message: str
    details: list[str] = []
