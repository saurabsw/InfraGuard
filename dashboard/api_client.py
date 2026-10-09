"""HTTP API client for InfraGuard backend.

Consumes ONLY published REST API endpoints. Never imports database models,
engine rules, or services directly (PRD §6, §11).
"""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any, BinaryIO

import httpx


class ApiClientError(Exception):
    """Exception raised when API request fails or returns an error."""

    def __init__(
        self, message: str, status_code: int | None = None, details: list[str] | None = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or []


class InfraGuardApiClient:
    """Client for interacting with InfraGuard FastAPI backend."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        client: httpx.Client | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self._custom_client = client

    def _client(self, timeout: float = 10.0):
        if self._custom_client is not None:
            return nullcontext(self._custom_client)
        return httpx.Client(base_url=self.base_url, timeout=timeout)

    def get_health(self) -> dict[str, Any]:
        """Check backend health status."""
        try:
            with self._client(timeout=5.0) as client:
                resp = client.get("/health")
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Backend health check failed: {exc}") from exc

    def get_providers(self) -> list[dict[str, Any]]:
        """Fetch supported providers and formats."""
        try:
            with self._client(timeout=5.0) as client:
                resp = client.get("/api/v1/providers")
                resp.raise_for_status()
                return resp.json().get("providers", [])
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to fetch providers: {exc}") from exc

    def get_rules(
        self,
        provider: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> dict[str, Any]:
        """Fetch security rules with optional filters."""
        params: dict[str, str] = {}
        if provider:
            params["provider"] = provider
        if severity:
            params["severity"] = severity
        if rule_id:
            params["rule_id"] = rule_id

        try:
            with self._client(timeout=5.0) as client:
                resp = client.get("/api/v1/rules", params=params)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to fetch rules: {exc}") from exc

    def submit_scan(
        self,
        provider: str,
        format_val: str,
        files: list[tuple[str, bytes | BinaryIO]],
    ) -> dict[str, Any]:
        """Submit configuration files for scanning."""
        if not files:
            raise ApiClientError("At least one file is required")

        data = {"provider": provider, "format": format_val}
        file_payload = [
            (
                "files",
                (filename, content if isinstance(content, bytes) else content.read(), "text/plain"),
            )
            for filename, content in files
        ]

        try:
            with self._client(timeout=60.0) as client:
                resp = client.post("/api/v1/scans", data=data, files=file_payload)
                if resp.status_code != 201:
                    err_json = (
                        resp.json()
                        if resp.headers.get("content-type", "").startswith("application/json")
                        else {}
                    )
                    msg = err_json.get("message") or f"Scan failed with status {resp.status_code}"
                    details = err_json.get("details", [])
                    raise ApiClientError(msg, status_code=resp.status_code, details=details)
                return resp.json()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Network error during scan submission: {exc}") from exc

    def get_scans(
        self,
        page: int = 1,
        page_size: int = 20,
        provider: str | None = None,
    ) -> dict[str, Any]:
        """Retrieve paginated scan history."""
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if provider:
            params["provider"] = provider

        try:
            with self._client(timeout=5.0) as client:
                resp = client.get("/api/v1/scans", params=params)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to fetch scan history: {exc}") from exc

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        """Retrieve detailed scan result and findings."""
        try:
            with self._client(timeout=10.0) as client:
                resp = client.get(f"/api/v1/scans/{scan_id}")
                if resp.status_code == 404:
                    raise ApiClientError(f"Scan '{scan_id}' not found", status_code=404)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to fetch scan details: {exc}") from exc

    def get_report(self, scan_id: str, fmt: str = "json") -> tuple[bytes, str]:
        """Export report and return (bytes_content, media_type)."""
        try:
            with self._client(timeout=10.0) as client:
                resp = client.get(f"/api/v1/scans/{scan_id}/report", params={"format": fmt})
                if resp.status_code == 404:
                    raise ApiClientError(f"Scan '{scan_id}' not found", status_code=404)
                resp.raise_for_status()
                media_type = resp.headers.get("content-type", "application/octet-stream")
                return resp.content, media_type
        except httpx.HTTPError as exc:
            raise ApiClientError(f"Failed to download report: {exc}") from exc
