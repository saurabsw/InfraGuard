"""Rule schemas for rule catalogue endpoint."""

from __future__ import annotations

from pydantic import BaseModel

from app.core.constants import Provider, Severity


class RuleResponse(BaseModel):
    """Metadata describing a single rule."""

    rule_id: str
    title: str
    description: str
    provider: Provider
    severity: Severity
    resource_types: list[str]
    rationale: str
    remediation: str
    references: list[str]
    secure_example: str | None = None


class RuleListResponse(BaseModel):
    """Response containing list of rules and metadata."""

    total: int
    policy_version: str
    rules: list[RuleResponse]
