"""Security rule evaluation engine.

Evaluates normalized resources against registered rules deterministically.
Never treats unsupported or indeterminate configurations as PASS (PRD §1, §7).
"""

from __future__ import annotations

from app.core.constants import EvaluationStatus, Severity
from app.engine.registry import PolicyRegistry, policy_registry
from app.engine.rule_base import EvaluationResult
from app.schemas.resource import NormalizedResource


class RuleEvaluator:
    """Evaluates normalized resources against policy rules."""

    def __init__(self, registry: PolicyRegistry | None = None):
        self.registry = registry or policy_registry

    def evaluate_resources(
        self,
        resources: list[NormalizedResource],
    ) -> list[EvaluationResult]:
        results: list[EvaluationResult] = []

        for res in resources:
            # Handle resources already identified as unsupported by the normalizer
            if res.evaluation_status == EvaluationStatus.UNSUPPORTED:
                results.append(
                    EvaluationResult(
                        rule_id="IG-UNSUPPORTED",
                        resource_id=res.resource_id,
                        resource_type=res.resource_type,
                        status=EvaluationStatus.UNSUPPORTED,
                        severity=Severity.LOW,
                        evidence=f"Resource type '{res.raw_type or res.resource_type}' is outside the supported MVP scope",
                        remediation="Review resource manually or wait for future parser/rule expansion",
                        source_file=res.source_file,
                        source_location=res.source_location,
                    )
                )
                continue

            # Find matching rules for this resource
            provider_rules = self.registry.get_rules_for_provider(res.provider)
            matching_rules = [
                r for r in provider_rules if res.resource_type in r.metadata().resource_types
            ]

            if not matching_rules:
                # Recognized provider resource, but no rules currently target this canonical type
                results.append(
                    EvaluationResult(
                        rule_id="IG-NO-RULE",
                        resource_id=res.resource_id,
                        resource_type=res.resource_type,
                        status=EvaluationStatus.UNSUPPORTED,
                        severity=Severity.LOW,
                        evidence=f"No security rules currently evaluate resource type '{res.resource_type}'",
                        remediation="No automated guardrails configured for this resource",
                        source_file=res.source_file,
                        source_location=res.source_location,
                    )
                )
                continue

            for rule in matching_rules:
                eval_res = rule.evaluate(res)
                # Ensure source file is preserved
                if not eval_res.source_file:
                    eval_res.source_file = res.source_file
                if not eval_res.source_location and res.source_location:
                    eval_res.source_location = res.source_location
                results.append(eval_res)

        return results
