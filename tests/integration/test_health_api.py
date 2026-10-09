"""Integration tests for the health endpoint."""

from __future__ import annotations


class TestHealthEndpoint:
    """GET /health integration tests."""

    def test_health_returns_200(self, client):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_response_body(self, client):
        data = client.get("/health").json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_health_version_matches_config(self, client):
        from app.core.config import settings

        data = client.get("/health").json()
        assert data["version"] == settings.app_version
