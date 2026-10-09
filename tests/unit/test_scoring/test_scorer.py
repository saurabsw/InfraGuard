"""Unit tests for Risk Scorer."""

from __future__ import annotations

from app.core.constants import EvaluationStatus, RiskBand, Severity
from app.engine.rule_base import EvaluationResult
from app.scoring.scorer import RiskScorer


def _make_eval_result(status: EvaluationStatus, severity: Severity) -> EvaluationResult:
    return EvaluationResult(
        rule_id="RULE-1",
        resource_id="res-1",
        resource_type="type-1",
        status=status,
        severity=severity,
        evidence="test evidence",
        remediation="fix it",
        source_file="test.tf",
    )


class TestRiskScorer:
    def test_perfect_score(self):
        scorer = RiskScorer()
        findings = [
            _make_eval_result(EvaluationStatus.PASS, Severity.CRITICAL),
            _make_eval_result(EvaluationStatus.PASS, Severity.HIGH),
        ]
        summary = scorer.calculate_score(findings)
        assert summary.risk_score == 100
        assert summary.risk_band == RiskBand.LOW
        assert summary.penalty_points == 0

    def test_single_critical_penalty(self):
        scorer = RiskScorer()
        findings = [
            _make_eval_result(EvaluationStatus.FAIL, Severity.CRITICAL),  # 25 penalty
        ]
        summary = scorer.calculate_score(findings)
        assert summary.risk_score == 75
        assert summary.risk_band == RiskBand.MODERATE
        assert summary.penalty_points == 25

    def test_multiple_penalties(self):
        scorer = RiskScorer()
        findings = [
            _make_eval_result(EvaluationStatus.FAIL, Severity.CRITICAL),  # 25
            _make_eval_result(EvaluationStatus.FAIL, Severity.HIGH),  # 15
            _make_eval_result(EvaluationStatus.FAIL, Severity.MEDIUM),  # 7
            _make_eval_result(EvaluationStatus.FAIL, Severity.LOW),  # 3
        ]  # Total penalty = 50 -> Score = 50 -> HIGH band
        summary = scorer.calculate_score(findings)
        assert summary.risk_score == 50
        assert summary.risk_band == RiskBand.HIGH
        assert summary.penalty_points == 50

    def test_score_never_below_zero(self):
        scorer = RiskScorer()
        findings = [
            _make_eval_result(EvaluationStatus.FAIL, Severity.CRITICAL)
            for _ in range(10)  # 250 penalty
        ]
        summary = scorer.calculate_score(findings)
        assert summary.risk_score == 0
        assert summary.risk_band == RiskBand.CRITICAL
