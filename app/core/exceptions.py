"""Application exception hierarchy.

All custom exceptions derive from InfraGuardError so they can be
caught by a single global handler in the API layer. Structured error
responses are built from these exceptions — no raw stack traces are
exposed to API clients (PRD §13).
"""

from __future__ import annotations


class InfraGuardError(Exception):
    """Base exception for all InfraGuard errors."""

    def __init__(self, message: str, *, error_code: str = "INTERNAL_ERROR"):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ValidationError(InfraGuardError):
    """Input validation failure (422)."""

    def __init__(self, message: str, details: list[str] | None = None):
        super().__init__(message, error_code="VALIDATION_ERROR")
        self.details = details or []


class UnsupportedProviderError(ValidationError):
    """Provider is not supported."""

    def __init__(self, provider: str):
        super().__init__(
            f"Unsupported provider: {provider}",
            details=["Supported providers: aws, azure, gcp"],
        )


class UnsupportedFormatError(ValidationError):
    """Format is not supported for the given provider."""

    def __init__(self, provider: str, fmt: str):
        super().__init__(
            f"Format '{fmt}' is not supported for provider '{provider}'",
            details=["Check GET /api/v1/providers for supported formats"],
        )


class FileSizeExceededError(ValidationError):
    """Uploaded file exceeds size limit."""

    def __init__(self, filename: str, size: int, limit: int):
        super().__init__(
            f"File '{filename}' ({size} bytes) exceeds limit ({limit} bytes)",
        )


class FileCountExceededError(ValidationError):
    """Too many files in a single scan."""

    def __init__(self, count: int, limit: int):
        super().__init__(
            f"Too many files ({count}), maximum is {limit}",
        )


class ParseError(InfraGuardError):
    """Configuration file could not be parsed."""

    def __init__(self, message: str, filename: str = ""):
        super().__init__(message, error_code="PARSE_ERROR")
        self.filename = filename


class ScanNotFoundError(InfraGuardError):
    """Requested scan does not exist."""

    def __init__(self, scan_id: str):
        super().__init__(
            f"Scan not found: {scan_id}",
            error_code="NOT_FOUND",
        )
