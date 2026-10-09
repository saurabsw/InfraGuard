"""Rule catalogue endpoint.

GET /api/v1/rules — list applicable rules with optional filters (PRD §9).
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.core.config import settings
from app.core.constants import Provider, Severity
from app.engine.registry import policy_registry
from app.schemas.rule import RuleListResponse, RuleResponse

router = APIRouter(prefix="/api/v1", tags=["rules"])


@router.get(
    "/rules",
    response_model=RuleListResponse,
    summary="List security rules",
    description="Returns all active security rules with optional filtering by provider, severity, and rule ID.",
)
async def list_rules(
    provider: Provider | None = Query(None, description="Filter rules by cloud provider"),
    severity: Severity | None = Query(None, description="Filter rules by severity level"),
    rule_id: str | None = Query(None, description="Filter by exact rule ID"),
) -> RuleListResponse:
    rules = policy_registry.filter_rules(
        provider=provider,
        severity=severity,
        rule_id=rule_id,
    )

    items = [
        RuleResponse(
            rule_id=r.metadata().rule_id,
            title=r.metadata().title,
            description=r.metadata().description,
            provider=r.metadata().provider,
            severity=r.metadata().severity,
            resource_types=r.metadata().resource_types,
            rationale=r.metadata().rationale,
            remediation=r.metadata().remediation,
            references=r.metadata().references,
            secure_example=r.metadata().secure_example,
        )
        for r in rules
    ]

    return RuleListResponse(
        total=len(items),
        policy_version=settings.policy_version,
        rules=items,
    )
