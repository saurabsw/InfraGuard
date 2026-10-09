"""Finding response schemas."""

from __future__ import annotations

from pydantic import BaseModel

from app.core.constants import EvaluationStatus, Provider, Severity


class FindingResponse(BaseModel):
    """A single security finding produced by a rule evaluation."""

    id: str
    rule_id: str
    provider: Provider
    severity: Severity
    status: EvaluationStatus
    resource_id: str
    resource_type: str
    source_file: str
    source_location: str | None = None
    evidence: str
    remediation: str
    reference_urls: list[str] = []
