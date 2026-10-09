"""Security and input validation tests for file uploads and scan submissions."""

from __future__ import annotations

import io


class TestUploadValidation:
    def test_unsupported_provider_rejected(self, client):
        files = [("files", ("main.tf", io.BytesIO(b'resource "test" {}'), "text/plain"))]
        resp = client.post(
            "/api/v1/scans", data={"provider": "oracle_cloud", "format": "terraform"}, files=files
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "VALIDATION_ERROR"
        assert "Unsupported provider" in data["message"]

    def test_unsupported_format_for_provider_rejected(self, client):
        files = [("files", ("main.tf", io.BytesIO(b'resource "test" {}'), "text/plain"))]
        resp = client.post(
            "/api/v1/scans", data={"provider": "azure", "format": "cloudformation"}, files=files
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "VALIDATION_ERROR"
        assert "not supported for provider" in data["message"]

    def test_invalid_file_extension_rejected(self, client):
        files = [("files", ("exploit.exe", io.BytesIO(b"binary data"), "application/octet-stream"))]
        resp = client.post(
            "/api/v1/scans", data={"provider": "aws", "format": "terraform"}, files=files
        )
        assert resp.status_code == 422
        data = resp.json()
        assert data["error"] == "VALIDATION_ERROR"
        assert "invalid extension" in data["message"]

    def test_oversized_file_rejected(self, client, monkeypatch):
        # Temporarily lower limit to 100 bytes for test
        from app.core.config import settings

        monkeypatch.setattr(settings, "max_file_size_bytes", 100)

        big_content = b"a" * 200
        files = [("files", ("big.tf", io.BytesIO(big_content), "text/plain"))]
        resp = client.post(
            "/api/v1/scans", data={"provider": "aws", "format": "terraform"}, files=files
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "exceeds limit" in data["message"]

    def test_file_count_limit_rejected(self, client, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "max_files_per_scan", 3)

        files = [
            (
                "files",
                (f"file_{i}.tf", io.BytesIO(b'resource "aws_s3_bucket" "b" {}'), "text/plain"),
            )
            for i in range(5)
        ]
        resp = client.post(
            "/api/v1/scans", data={"provider": "aws", "format": "terraform"}, files=files
        )
        assert resp.status_code == 422
        data = resp.json()
        assert "Too many files" in data["message"]
