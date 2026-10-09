"""Integration tests testing InfraGuardApiClient against real FastAPI application routes."""

from __future__ import annotations

from dashboard.api_client import InfraGuardApiClient


class TestDashboardIntegrationFlow:
    def test_client_against_live_test_client(self, client):
        # client fixture is fastapi.testclient.TestClient from conftest.py
        api_client = InfraGuardApiClient(client=client)

        # 1. Health check
        health = api_client.get_health()
        assert health["status"] == "healthy"

        # 2. Provider discovery
        providers = api_client.get_providers()
        assert len(providers) == 3
        aws_prov = next(p for p in providers if p["id"] == "aws")
        assert len(aws_prov["supported_formats"]) == 2

        # 3. Rule discovery
        rules = api_client.get_rules(provider="aws")
        assert rules["total"] == 11

        # 4. Scan submission
        sample_tf = b'resource "aws_db_instance" "my_db" { publicly_accessible = true }'
        scan_res = api_client.submit_scan("aws", "terraform", [("test.tf", sample_tf)])
        scan_id = scan_res["scan_id"]
        assert scan_res["status"] == "completed"

        # 5. Fetch scan details
        fetched_scan = api_client.get_scan(scan_id)
        assert fetched_scan["scan_id"] == scan_id
        assert len(fetched_scan["findings"]) >= 1

        # 6. Fetch scan history
        history = api_client.get_scans(page=1, page_size=10)
        assert history["total"] >= 1
        assert any(item["scan_id"] == scan_id for item in history["items"])

        # 7. Report export
        json_report, media_type = api_client.get_report(scan_id, fmt="json")
        assert b"my_db" in json_report
        assert "application/json" in media_type

        csv_report, csv_media = api_client.get_report(scan_id, fmt="csv")
        assert b"finding_id,scan_id" in csv_report
        assert "text/csv" in csv_media
