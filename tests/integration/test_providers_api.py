"""Integration tests for the provider discovery endpoint."""

from __future__ import annotations


class TestProvidersEndpoint:
    """GET /api/v1/providers integration tests."""

    def test_returns_200(self, client):
        response = client.get("/api/v1/providers")
        assert response.status_code == 200

    def test_returns_three_providers(self, client):
        data = client.get("/api/v1/providers").json()
        assert len(data["providers"]) == 3

    def test_provider_ids(self, client):
        data = client.get("/api/v1/providers").json()
        ids = {p["id"] for p in data["providers"]}
        assert ids == {"aws", "azure", "gcp"}

    def test_aws_has_terraform_and_cloudformation(self, client):
        data = client.get("/api/v1/providers").json()
        aws = next(p for p in data["providers"] if p["id"] == "aws")
        format_ids = {f["id"] for f in aws["supported_formats"]}
        assert "terraform" in format_ids
        assert "cloudformation" in format_ids

    def test_azure_has_terraform_only(self, client):
        data = client.get("/api/v1/providers").json()
        azure = next(p for p in data["providers"] if p["id"] == "azure")
        format_ids = {f["id"] for f in azure["supported_formats"]}
        assert format_ids == {"terraform"}

    def test_gcp_has_terraform_only(self, client):
        data = client.get("/api/v1/providers").json()
        gcp = next(p for p in data["providers"] if p["id"] == "gcp")
        format_ids = {f["id"] for f in gcp["supported_formats"]}
        assert format_ids == {"terraform"}

    def test_terraform_format_has_tf_extension(self, client):
        data = client.get("/api/v1/providers").json()
        aws = next(p for p in data["providers"] if p["id"] == "aws")
        tf = next(f for f in aws["supported_formats"] if f["id"] == "terraform")
        assert ".tf" in tf["extensions"]

    def test_cloudformation_format_extensions(self, client):
        data = client.get("/api/v1/providers").json()
        aws = next(p for p in data["providers"] if p["id"] == "aws")
        cf = next(f for f in aws["supported_formats"] if f["id"] == "cloudformation")
        assert set(cf["extensions"]) == {".yaml", ".yml", ".json"}

    def test_provider_has_name(self, client):
        data = client.get("/api/v1/providers").json()
        for p in data["providers"]:
            assert "name" in p
            assert len(p["name"]) > 0

    def test_response_structure(self, client):
        """Verify the exact shape matches our API contract."""
        data = client.get("/api/v1/providers").json()
        assert "providers" in data
        for p in data["providers"]:
            assert "id" in p
            assert "name" in p
            assert "supported_formats" in p
            for f in p["supported_formats"]:
                assert "id" in f
                assert "name" in f
                assert "extensions" in f
