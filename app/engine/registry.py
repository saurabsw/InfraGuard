"""Policy and Rule Registry.

Maintains all active security rules and provides filtering by provider,
severity, and rule ID (PRD §6, §7).
"""

from __future__ import annotations

from app.core.constants import Provider, Severity
from app.engine.rule_base import RuleMetadata, SecurityRule
from app.rules.aws import (
    EBSVolumeEncryptionRule,
    IAMWildcardPermissionsRule,
    RDSPublicAccessRule,
    RDSStorageEncryptionRule,
    S3BlockPublicAccessRule,
    S3BucketLoggingRule,
    S3PublicReadRule,
    S3PublicWriteRule,
    SecurityGroupPermissiveRule,
    SecurityGroupRDPRule,
    SecurityGroupSSHRule,
)
from app.rules.azure import (
    DatabasePublicAccessRule,
    NSGOverlyPermissiveRule,
    NSGRDPRule,
    NSGSSHRule,
    StorageInfrastructureEncryptionRule,
    StoragePublicBlobRule,
    StorageSecureTransferRule,
)
from app.rules.gcp import (
    FirewallPermissiveRule,
    FirewallRDPRule,
    FirewallSSHRule,
    ProjectIAMBroadGrantsRule,
    StoragePublicAccessPreventionRule,
    StoragePublicIAMRule,
    StorageUniformAccessRule,
)


class PolicyRegistry:
    """Registry of all implemented security rules."""

    def __init__(self):
        self._rules: list[SecurityRule] = [
            # AWS (11)
            S3PublicReadRule(),
            S3PublicWriteRule(),
            S3BlockPublicAccessRule(),
            SecurityGroupSSHRule(),
            SecurityGroupRDPRule(),
            SecurityGroupPermissiveRule(),
            RDSPublicAccessRule(),
            RDSStorageEncryptionRule(),
            EBSVolumeEncryptionRule(),
            IAMWildcardPermissionsRule(),
            S3BucketLoggingRule(),
            # Azure (7)
            StoragePublicBlobRule(),
            NSGSSHRule(),
            NSGRDPRule(),
            StorageSecureTransferRule(),
            StorageInfrastructureEncryptionRule(),
            NSGOverlyPermissiveRule(),
            DatabasePublicAccessRule(),
            # GCP (7)
            StoragePublicIAMRule(),
            FirewallSSHRule(),
            FirewallRDPRule(),
            FirewallPermissiveRule(),
            StorageUniformAccessRule(),
            StoragePublicAccessPreventionRule(),
            ProjectIAMBroadGrantsRule(),
        ]

    def get_all_rules(self) -> list[SecurityRule]:
        return list(self._rules)

    def get_rules_for_provider(self, provider: Provider) -> list[SecurityRule]:
        return [r for r in self._rules if r.metadata().provider == provider]

    def filter_rules(
        self,
        provider: Provider | None = None,
        severity: Severity | None = None,
        rule_id: str | None = None,
    ) -> list[SecurityRule]:
        out = self._rules
        if provider:
            out = [r for r in out if r.metadata().provider == provider]
        if severity:
            out = [r for r in out if r.metadata().severity == severity]
        if rule_id:
            out = [r for r in out if r.metadata().rule_id == rule_id]
        return out

    def get_rule_by_id(self, rule_id: str) -> SecurityRule | None:
        for r in self._rules:
            if r.metadata().rule_id == rule_id:
                return r
        return None

    def get_rule_metadata_list(
        self,
        provider: Provider | None = None,
        severity: Severity | None = None,
    ) -> list[RuleMetadata]:
        rules = self.filter_rules(provider=provider, severity=severity)
        return [r.metadata() for r in rules]


# Global singleton registry
policy_registry = PolicyRegistry()
