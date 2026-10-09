"""Azure Security Rules (IG-AZ-001 to IG-AZ-007)."""

from __future__ import annotations

from typing import Any

from app.core.constants import EvaluationStatus, Provider, Severity
from app.engine.rule_base import EvaluationResult, RuleMetadata, SecurityRule
from app.schemas.resource import NormalizedResource


def _check_nsg_security_rules(
    rules_list: list[dict[str, Any]], target_port: int, check_all: bool = False
) -> tuple[bool, str]:
    """Helper to evaluate Azure NSG rules for open internet access."""
    internet_prefixes = {"*", "0.0.0.0/0", "internet"}

    for rule in rules_list:
        if not isinstance(rule, dict):
            continue

        direction = str(rule.get("direction", "")).lower()
        access = str(rule.get("access", "")).lower()

        if direction != "inbound" or access != "allow":
            continue

        src = rule.get("source_address_prefix") or rule.get("source_address_prefixes") or []
        if isinstance(src, str):
            src = [src]
        src_set = {str(s).lower() for s in src}

        is_internet = bool(src_set & internet_prefixes)
        if not is_internet:
            continue

        dest_port = rule.get("destination_port_range") or rule.get("destination_port_ranges") or []
        if isinstance(dest_port, (str, int)):
            dest_port = [str(dest_port)]
        dest_set = {str(p).strip().lower() for p in dest_port}

        protocol = str(rule.get("protocol", "")).lower()

        if check_all:
            if ("*" in dest_set or "0-65535" in dest_set) and protocol in ("*", "any"):
                return True, "NSG allows all inbound traffic from Internet (*)"
        else:
            if "*" in dest_set:
                return True, f"Port {target_port} allowed via wildcard destination port (*)"
            if str(target_port) in dest_set:
                return True, f"Port {target_port} exposed inbound from {', '.join(src_set)}"

    return False, ""


class StoragePublicBlobRule(SecurityRule):
    """IG-AZ-001: Detect storage accounts allowing public blob access."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-001",
            title="Storage Account Allows Public Blob Access",
            description="Detect Azure storage accounts where public blob or nested item access is allowed.",
            provider=Provider.AZURE,
            severity=Severity.HIGH,
            resource_types=["storage_account"],
            rationale="Public blob access permits unauthenticated downloads of containers and blobs.",
            remediation="Set allow_nested_items_to_be_public = false or allow_blob_public_access = false.",
            references=[
                "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-configure"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        val = props.get("allow_nested_items_to_be_public")
        if val is None:
            val = props.get("allow_blob_public_access")

        if val is True or str(val).lower() == "true":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="Storage account enables public blob / nested item access",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )
        elif val is False or str(val).lower() == "false":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Storage account explicitly disables public blob access",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.NOT_EVALUATED,
            severity=meta.severity,
            evidence="Public blob access configuration is omitted or indeterminate",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class NSGSSHRule(SecurityRule):
    """IG-AZ-002: Detect network security rules exposing SSH to the internet."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-002",
            title="NSG Inbound SSH Exposed to Internet (Port 22)",
            description="Detect Azure Network Security Groups allowing internet-wide inbound SSH on port 22.",
            provider=Provider.AZURE,
            severity=Severity.CRITICAL,
            resource_types=["network_security_group", "network_security_rule"],
            rationale="Direct inbound SSH from the internet risks remote brute force and credential theft.",
            remediation="Restrict inbound port 22 to specific corporate IP addresses or use Azure Bastion.",
            references=[
                "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        rules = props.get("security_rule") or []
        if isinstance(rules, dict):
            rules = [rules]
        if not rules and resource.resource_type == "network_security_rule":
            rules = [props]

        violation, ev = _check_nsg_security_rules(rules, 22)
        if violation:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence=ev,
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="Inbound SSH (port 22) is not exposed to the internet",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class NSGRDPRule(SecurityRule):
    """IG-AZ-003: Detect network security rules exposing RDP to the internet."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-003",
            title="NSG Inbound RDP Exposed to Internet (Port 3389)",
            description="Detect Azure Network Security Groups allowing internet-wide inbound RDP on port 3389.",
            provider=Provider.AZURE,
            severity=Severity.CRITICAL,
            resource_types=["network_security_group", "network_security_rule"],
            rationale="Direct inbound RDP exposes Windows VMs to credential spraying and ransomware entry.",
            remediation="Restrict inbound port 3389 to trusted IP ranges or use Azure Bastion.",
            references=[
                "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        rules = props.get("security_rule") or []
        if isinstance(rules, dict):
            rules = [rules]
        if not rules and resource.resource_type == "network_security_rule":
            rules = [props]

        violation, ev = _check_nsg_security_rules(rules, 3389)
        if violation:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence=ev,
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="Inbound RDP (port 3389) is not exposed to the internet",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class StorageSecureTransferRule(SecurityRule):
    """IG-AZ-004: Detect storage accounts without explicitly enabled secure transfer."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-004",
            title="Storage Account Secure Transfer Disabled",
            description="Detect Azure storage accounts that allow unencrypted HTTP traffic.",
            provider=Provider.AZURE,
            severity=Severity.HIGH,
            resource_types=["storage_account"],
            rationale="Unencrypted HTTP requests risk eavesdropping and man-in-the-middle attacks.",
            remediation="Set enable_https_traffic_only = true (or https_traffic_only_enabled = true).",
            references=[
                "https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        val = props.get("enable_https_traffic_only")
        if val is None:
            val = props.get("https_traffic_only_enabled")

        if val is False or str(val).lower() == "false":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="Storage account explicitly disables secure HTTPS transfer",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )
        elif val is True or str(val).lower() == "true":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Storage account enables secure HTTPS transfer",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.NOT_EVALUATED,
            severity=meta.severity,
            evidence="Secure transfer setting is omitted or indeterminate",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class StorageInfrastructureEncryptionRule(SecurityRule):
    """IG-AZ-005: Detect storage accounts without infrastructure encryption enabled."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-005",
            title="Storage Account Infrastructure Encryption Missing",
            description="Detect Azure storage accounts without double infrastructure encryption enabled.",
            provider=Provider.AZURE,
            severity=Severity.MEDIUM,
            resource_types=["storage_account"],
            rationale="Infrastructure encryption provides double encryption at rest at the hardware level.",
            remediation="Set infrastructure_encryption_enabled = true.",
            references=[
                "https://learn.microsoft.com/azure/storage/common/infrastructure-encryption-enable"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        val = props.get("infrastructure_encryption_enabled")
        if val is True or str(val).lower() == "true":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Infrastructure encryption is enabled",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.FAIL,
            severity=meta.severity,
            evidence="Storage account does not explicitly enable infrastructure_encryption_enabled",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class NSGOverlyPermissiveRule(SecurityRule):
    """IG-AZ-006: Detect overly permissive network security rules."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-006",
            title="NSG Overly Permissive Inbound Traffic",
            description="Detect inbound rules allowing all protocols and all ports from any internet source.",
            provider=Provider.AZURE,
            severity=Severity.HIGH,
            resource_types=["network_security_group", "network_security_rule"],
            rationale="Allowing any traffic from the internet bypasses perimeter security.",
            remediation="Restrict protocol, destination ports, and source prefixes.",
            references=[
                "https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        rules = props.get("security_rule") or []
        if isinstance(rules, dict):
            rules = [rules]
        if not rules and resource.resource_type == "network_security_rule":
            rules = [props]

        violation, ev = _check_nsg_security_rules(rules, 0, check_all=True)
        if violation:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence=ev,
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="NSG does not contain blanket allow-all inbound rules from Internet",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class DatabasePublicAccessRule(SecurityRule):
    """IG-AZ-007: Detect databases configured for public network access."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AZ-007",
            title="Azure Database Public Network Access Enabled",
            description="Detect Azure SQL, PostgreSQL, or MySQL servers with public network access enabled.",
            provider=Provider.AZURE,
            severity=Severity.CRITICAL,
            resource_types=["sql_server", "postgresql_server", "mysql_server"],
            rationale="Databases exposed to public networks are vulnerable to internet scanning and exploitation.",
            remediation="Set public_network_access_enabled = false and configure private endpoints.",
            references=[
                "https://learn.microsoft.com/azure/azure-sql/database/connectivity-architecture"
            ],
        )

    def evaluate(self, resource: NormalizedResource) -> EvaluationResult:
        meta = self.metadata()
        if resource.resource_type not in meta.resource_types:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.UNSUPPORTED,
                severity=meta.severity,
                evidence=f"Resource type {resource.resource_type} not supported by rule",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        props = resource.properties
        val = props.get("public_network_access_enabled")

        if val is True or str(val).lower() == "true":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="Database server is configured with public_network_access_enabled = true",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )
        elif val is False or str(val).lower() == "false":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Database server disables public network access",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.NOT_EVALUATED,
            severity=meta.severity,
            evidence="Public network access setting is omitted or indeterminate",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )
