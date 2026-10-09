"""Unit tests for dashboard InfraGuardApiClient."""

from __future__ import annotations

import httpx
import pytest
from dashboard.api_client import ApiClientError, InfraGuardApiClient


def _mock_resp(status_code: int, **kwargs) -> httpx.Response:
    req = httpx.Request("GET", "http://test")
    return httpx.Response(status_code, request=req, **kwargs)


class TestInfraGuardApiClient:
    def test_get_health_success(self, monkeypatch):
        def mock_get(self, url, **kwargs):
            return _mock_resp(200, json={"status": "healthy", "version": "1.0.0"})

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        client = InfraGuardApiClient()
        health = client.get_health()
        assert health["status"] == "healthy"
        assert health["version"] == "1.0.0"

    def test_get_providers_success(self, monkeypatch):
        def mock_get(self, url, **kwargs):
            return _mock_resp(200, json={"providers": [{"id": "aws", "name": "AWS"}]})

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        client = InfraGuardApiClient()
        providers = client.get_providers()
        assert len(providers) == 1
        assert providers[0]["id"] == "aws"

    def test_get_rules_with_filters(self, monkeypatch):
        captured_params = {}

        def mock_get(self, url, params=None, **kwargs):
            captured_params.update(params or {})
            return _mock_resp(200, json={"total": 5, "rules": []})

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        client = InfraGuardApiClient()
        client.get_rules(provider="aws", severity="CRITICAL", rule_id="IG-AWS-001")
        assert captured_params["provider"] == "aws"
        assert captured_params["severity"] == "CRITICAL"
        assert captured_params["rule_id"] == "IG-AWS-001"

    def test_submit_scan_success(self, monkeypatch):
        def mock_post(self, url, data=None, files=None, **kwargs):
            return _mock_resp(201, json={"scan_id": "scan-123", "status": "completed"})

        monkeypatch.setattr(httpx.Client, "post", mock_post)

        client = InfraGuardApiClient()
        res = client.submit_scan(
            "aws", "terraform", [("test.tf", b'resource "aws_s3_bucket" "b" {}')]
        )
        assert res["scan_id"] == "scan-123"

    def test_submit_scan_empty_files_raises_error(self):
        client = InfraGuardApiClient()
        with pytest.raises(ApiClientError) as exc_info:
            client.submit_scan("aws", "terraform", [])
        assert "At least one file is required" in exc_info.value.message

    def test_get_scan_not_found(self, monkeypatch):
        def mock_get(self, url, **kwargs):
            return _mock_resp(404, json={"error": "NOT_FOUND", "message": "Not found"})

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        client = InfraGuardApiClient()
        with pytest.raises(ApiClientError) as exc_info:
            client.get_scan("non-existent-uuid")
        assert exc_info.value.status_code == 404

    def test_get_report_success(self, monkeypatch):
        def mock_get(self, url, **kwargs):
            return _mock_resp(
                200, content=b'{"scan_id": "1"}', headers={"content-type": "application/json"}
            )

        monkeypatch.setattr(httpx.Client, "get", mock_get)

        client = InfraGuardApiClient()
        content, media_type = client.get_report("1", fmt="json")
        assert content == b'{"scan_id": "1"}'
        assert media_type == "application/json"
