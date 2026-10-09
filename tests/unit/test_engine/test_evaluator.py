"""Unit tests for Rule Evaluator."""

from __future__ import annotations

from app.core.constants import EvaluationStatus, Provider
from app.engine.evaluator import RuleEvaluator
from app.schemas.resource import NormalizedResource


class TestRuleEvaluator:
    def test_evaluates_applicable_rules(self):
        evaluator = RuleEvaluator()
        res = NormalizedResource(
            provider=Provider.AWS,
            resource_type="rds_instance",
            resource_id="db1",
            source_file="main.tf",
            properties={"publicly_accessible": True, "storage_encrypted": False},
        )
        findings = evaluator.evaluate_resources([res])
        rule_ids = {f.rule_id for f in findings}
        assert "IG-AWS-007" in rule_ids
        assert "IG-AWS-008" in rule_ids
        # Both are FAIL
        fail_rules = {f.rule_id for f in findings if f.status == EvaluationStatus.FAIL}
        assert "IG-AWS-007" in fail_rules
        assert "IG-AWS-008" in fail_rules

    def test_unsupported_resource_handled_honestly(self):
        evaluator = RuleEvaluator()
        res = NormalizedResource(
            provider=Provider.AWS,
            resource_type="aws_unknown_thing",
            resource_id="u1",
            source_file="main.tf",
            properties={},
            evaluation_status=EvaluationStatus.UNSUPPORTED,
        )
        findings = evaluator.evaluate_resources([res])
        assert len(findings) == 1
        assert findings[0].status == EvaluationStatus.UNSUPPORTED
        assert "outside the supported" in findings[0].evidence
