"""Unit tests for Policy Registry."""

from __future__ import annotations

from app.core.constants import Provider, Severity
from app.engine.registry import policy_registry


class TestPolicyRegistry:
    def test_total_rule_count(self):
        rules = policy_registry.get_all_rules()
        assert len(rules) == 25

    def test_aws_rule_count(self):
        aws_rules = policy_registry.get_rules_for_provider(Provider.AWS)
        assert len(aws_rules) == 11

    def test_azure_rule_count(self):
        azure_rules = policy_registry.get_rules_for_provider(Provider.AZURE)
        assert len(azure_rules) == 7

    def test_gcp_rule_count(self):
        gcp_rules = policy_registry.get_rules_for_provider(Provider.GCP)
        assert len(gcp_rules) == 7

    def test_filter_by_severity(self):
        critical_rules = policy_registry.filter_rules(severity=Severity.CRITICAL)
        assert len(critical_rules) > 0
        assert all(r.metadata().severity == Severity.CRITICAL for r in critical_rules)

    def test_filter_by_rule_id(self):
        rule = policy_registry.get_rule_by_id("IG-AWS-001")
        assert rule is not None
        assert rule.metadata().title == "S3 Public Read Access"
