"""Base security rule interfaces and evaluation result dataclasses.

Rules must be pure, deterministic functions of normalized resource data.
The rule engine must not depend on FastAPI, Streamlit, or SQLAlchemy (PRD §6).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from app.core.constants import EvaluationStatus, Provider, Severity
from app.core.redaction import redact_text
from app.schemas.resource import NormalizedResource


@dataclass
class RuleMetadata:
    """Metadata describing a security rule."""

    rule_id: str
    title: str
    description: str
    provider: Provider
    severity: Severity
    resource_types: list[str]  # Canonical resource types this rule inspects
    rationale: str
    remediation: str
    references: list[str] = field(default_factory=list)
    secure_example: str | None = None


@dataclass
class EvaluationResult:
    """The outcome of evaluating a rule against a normalized resource."""

    rule_id: str
    resource_id: str
    resource_type: str
    status: EvaluationStatus
    severity: Severity
    evidence: str
    remediation: str
    source_file: str
    source_location: str | None = None
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.evidence:
            self.evidence = redact_text(self.evidence)


class SecurityRule(ABC):
    """Abstract base class for all security rules."""

    @abstractmethod
    def metadata(self) -> RuleMetadata:
        """Return static metadata for this rule."""
        ...

    @abstractmethod
    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        """Evaluate a single normalized resource.

        - Return PASS if configuration explicitly satisfies the security control.
        - Return FAIL if a violation is detected.
        - Return NOT_EVALUATED if required attributes are missing/indeterminate.
        - Return UNSUPPORTED if resource is outside the rule's scope.
        """
        ...
