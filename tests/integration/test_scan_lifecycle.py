"""Integration tests covering complete scan lifecycle through API endpoints."""

from __future__ import annotations

import io


class TestScanLifecycle:
    def test_full_scan_lifecycle_terraform_aws(self, client):
        # 1. Submit Scan via multipart/form-data
        content = """
        resource "aws_db_instance" "test_db" {
          allocated_storage   = 10
          engine              = "postgres"
          instance_class      = "db.t3.micro"
          publicly_accessible = true
          storage_encrypted   = false
        }
        """
        files = [("files", ("main.tf", io.BytesIO(content.encode("utf-8")), "text/plain"))]
        data = {"provider": "aws", "format": "terraform"}

        response = client.post("/api/v1/scans", data=data, files=files)
        assert response.status_code == 201
        scan_data = response.json()

        scan_id = scan_data["scan_id"]
        assert scan_data["provider"] == "aws"
        assert scan_data["format"] == "terraform"
        assert scan_data["status"] == "completed"
        assert scan_data["summary"]["total_resources"] == 1
        assert scan_data["summary"]["resources_evaluated"] == 1
        assert len(scan_data["findings"]) >= 2  # RDS public + unencrypted

        # 2. Retrieve Scan by ID
        get_resp = client.get(f"/api/v1/scans/{scan_id}")
        assert get_resp.status_code == 200
        get_data = get_resp.json()
        assert get_data["scan_id"] == scan_id
        assert get_data["summary"]["risk_score"] == scan_data["summary"]["risk_score"]

        # 3. Retrieve Scan History (Pagination)
        hist_resp = client.get("/api/v1/scans?page=1&page_size=10")
        assert hist_resp.status_code == 200
        hist_data = hist_resp.json()
        assert hist_data["total"] >= 1
        assert any(item["scan_id"] == scan_id for item in hist_data["items"])

        # 4. Export JSON Report
        json_report_resp = client.get(f"/api/v1/scans/{scan_id}/report?format=json")
        assert json_report_resp.status_code == 200
        assert "application/json" in json_report_resp.headers["content-type"]
        report_json = json_report_resp.json()
        assert report_json["scan_id"] == scan_id
        assert len(report_json["findings"]) >= 2

        # 5. Export CSV Report
        csv_report_resp = client.get(f"/api/v1/scans/{scan_id}/report?format=csv")
        assert csv_report_resp.status_code == 200
        assert "text/csv" in csv_report_resp.headers["content-type"]
        csv_text = csv_report_resp.text
        assert "finding_id,scan_id,rule_id" in csv_text
        assert "IG-AWS-007" in csv_text

    def test_get_nonexistent_scan_returns_404(self, client):
        resp = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404
        assert resp.json()["error"] == "NOT_FOUND"

    def test_export_nonexistent_scan_returns_404(self, client):
        resp = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/report")
        assert resp.status_code == 404
