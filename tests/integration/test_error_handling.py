"""Integration tests for global error handling."""

from __future__ import annotations


class TestErrorHandling:
    """Verify structured error responses for common error cases."""

    def test_404_for_unknown_route(self, client):
        """Unknown routes should return 404 (FastAPI default)."""
        response = client.get("/api/v1/nonexistent")
        assert response.status_code in (404, 405)

    def test_docs_endpoint_exists(self, client):
        """OpenAPI docs should be available at /docs."""
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_json_exists(self, client):
        """OpenAPI JSON schema should be available."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "paths" in data
        assert "/health" in data["paths"]
        assert "/api/v1/providers" in data["paths"]
