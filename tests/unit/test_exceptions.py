"""Unit tests for exception hierarchy."""

from __future__ import annotations

from app.core.exceptions import (
    FileCountExceededError,
    FileSizeExceededError,
    InfraGuardError,
    ParseError,
    ScanNotFoundError,
    UnsupportedFormatError,
    UnsupportedProviderError,
    ValidationError,
)


class TestExceptionHierarchy:
    """All custom exceptions derive from InfraGuardError."""

    def test_base_error(self):
        e = InfraGuardError("test")
        assert str(e) == "test"
        assert e.error_code == "INTERNAL_ERROR"
        assert e.message == "test"

    def test_validation_error(self):
        e = ValidationError("bad input", details=["field: required"])
        assert isinstance(e, InfraGuardError)
        assert e.error_code == "VALIDATION_ERROR"
        assert e.details == ["field: required"]

    def test_unsupported_provider(self):
        e = UnsupportedProviderError("oracle")
        assert isinstance(e, ValidationError)
        assert "oracle" in e.message

    def test_unsupported_format(self):
        e = UnsupportedFormatError("azure", "cloudformation")
        assert isinstance(e, ValidationError)
        assert "azure" in e.message
        assert "cloudformation" in e.message

    def test_file_size_exceeded(self):
        e = FileSizeExceededError("big.tf", 10_000_000, 5_242_880)
        assert isinstance(e, ValidationError)
        assert "big.tf" in e.message

    def test_file_count_exceeded(self):
        e = FileCountExceededError(50, 20)
        assert isinstance(e, ValidationError)
        assert "50" in e.message

    def test_parse_error(self):
        e = ParseError("invalid HCL", filename="bad.tf")
        assert isinstance(e, InfraGuardError)
        assert e.error_code == "PARSE_ERROR"
        assert e.filename == "bad.tf"

    def test_scan_not_found(self):
        e = ScanNotFoundError("abc-123")
        assert isinstance(e, InfraGuardError)
        assert e.error_code == "NOT_FOUND"
        assert "abc-123" in e.message
