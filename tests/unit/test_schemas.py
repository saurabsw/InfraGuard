"""Unit tests for Pydantic schemas."""

from __future__ import annotations

from app.schemas.common import ErrorResponse
from app.schemas.health import HealthResponse
from app.schemas.providers import FormatSchema, ProviderSchema, ProvidersResponse


class TestErrorResponse:
    def test_basic_error(self):
        e = ErrorResponse(error="TEST", message="something broke")
        assert e.error == "TEST"
        assert e.message == "something broke"
        assert e.details == []

    def test_error_with_details(self):
        e = ErrorResponse(
            error="VALIDATION_ERROR",
            message="Invalid input",
            details=["field x is required"],
        )
        assert len(e.details) == 1

    def test_serialization(self):
        e = ErrorResponse(error="TEST", message="msg")
        d = e.model_dump()
        assert d["error"] == "TEST"
        assert d["message"] == "msg"
        assert d["details"] == []


class TestHealthResponse:
    def test_health(self):
        h = HealthResponse(status="healthy", version="1.0.0")
        assert h.status == "healthy"
        assert h.version == "1.0.0"


class TestProviderSchemas:
    def test_format_schema(self):
        f = FormatSchema(id="terraform", name="Terraform HCL", extensions=[".tf"])
        assert f.id == "terraform"

    def test_provider_schema(self):
        p = ProviderSchema(
            id="aws",
            name="Amazon Web Services",
            supported_formats=[
                FormatSchema(id="terraform", name="Terraform HCL", extensions=[".tf"]),
            ],
        )
        assert p.id == "aws"
        assert len(p.supported_formats) == 1

    def test_providers_response(self):
        r = ProvidersResponse(
            providers=[
                ProviderSchema(
                    id="aws",
                    name="AWS",
                    supported_formats=[],
                ),
            ]
        )
        assert len(r.providers) == 1
