"""Risk scoring service.

Computes explainable, deterministic risk scores based on finding severity
penalties per PRD §8.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.constants import (
    SEVERITY_PENALTIES,
    EvaluationStatus,
    RiskBand,
    Severity,
)
from app.engine.rule_base import EvaluationResult


@dataclass
class ScoreSummary:
    """Summary of scan findings, score, and distribution."""

    risk_score: int
    risk_band: RiskBand
    total_findings: int
    severity_counts: dict[str, int] = field(default_factory=dict)
    status_counts: dict[str, int] = field(default_factory=dict)
    penalty_points: int = 0


class RiskScorer:
    """Calculates risk scores and score bands from evaluation results."""

    def calculate_score(self, findings: list[EvaluationResult]) -> ScoreSummary:
        severity_counts = {s.value: 0 for s in Severity}
        status_counts = {st.value: 0 for st in EvaluationStatus}

        total_penalty = 0

        for f in findings:
            # Count by status
            status_key = f.status.value if isinstance(f.status, EvaluationStatus) else str(f.status)
            status_counts[status_key] = status_counts.get(status_key, 0) + 1

            # Only FAIL findings contribute to penalty deduction
            if f.status == EvaluationStatus.FAIL:
                sev_enum = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
                sev_key = sev_enum.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

                penalty = SEVERITY_PENALTIES.get(sev_enum, 0)
                total_penalty += penalty

        # Score formula: max(0, 100 - total_penalties)
        score = max(0, 100 - total_penalty)

        # Score bands (PRD §8)
        band: RiskBand
        if score >= 90:
            band = RiskBand.LOW
        elif score >= 70:
            band = RiskBand.MODERATE
        elif score >= 40:
            band = RiskBand.HIGH
        else:
            band = RiskBand.CRITICAL

        return ScoreSummary(
            risk_score=score,
            risk_band=band,
            total_findings=len(findings),
            severity_counts=severity_counts,
            status_counts=status_counts,
            penalty_points=total_penalty,
        )
