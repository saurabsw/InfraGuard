"""Integration tests for rules catalogue endpoint (GET /api/v1/rules)."""

from __future__ import annotations


class TestRulesApi:
    def test_list_all_rules(self, client):
        response = client.get("/api/v1/rules")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 25
        assert len(data["rules"]) == 25
        assert data["policy_version"] == "1.0.0"

    def test_filter_by_aws_provider(self, client):
        response = client.get("/api/v1/rules?provider=aws")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 11
        assert all(r["provider"] == "aws" for r in data["rules"])

    def test_filter_by_azure_provider(self, client):
        response = client.get("/api/v1/rules?provider=azure")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 7
        assert all(r["provider"] == "azure" for r in data["rules"])

    def test_filter_by_gcp_provider(self, client):
        response = client.get("/api/v1/rules?provider=gcp")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 7
        assert all(r["provider"] == "gcp" for r in data["rules"])

    def test_filter_by_severity(self, client):
        response = client.get("/api/v1/rules?severity=CRITICAL")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] > 0
        assert all(r["severity"] == "CRITICAL" for r in data["rules"])

    def test_filter_by_exact_rule_id(self, client):
        response = client.get("/api/v1/rules?rule_id=IG-AWS-004")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["rules"][0]["rule_id"] == "IG-AWS-004"
        assert "SSH" in data["rules"][0]["title"]
