"""GCP Security Rules (IG-GCP-001 to IG-GCP-007)."""

from __future__ import annotations

from typing import Any

from app.core.constants import EvaluationStatus, Provider, Severity
from app.engine.rule_base import EvaluationResult, RuleMetadata, SecurityRule
from app.schemas.resource import NormalizedResource

PUBLIC_GCP_MEMBERS = {"allusers", "allauthenticatedusers"}


def _check_gcp_firewall_ports(
    allow_blocks: list[dict[str, Any]],
    source_ranges: list[str],
    target_port: int,
    check_all: bool = False,
) -> tuple[bool, str]:
    """Helper to evaluate Google Compute Firewall rules."""
    src_set = {str(s).strip() for s in source_ranges}
    is_open = (
        "0.0.0.0/0" in src_set or not src_set
    )  # In GCP, omitting source_ranges defaults to 0.0.0.0/0!

    if not is_open:
        return False, ""

    for block in allow_blocks:
        if not isinstance(block, dict):
            continue
        proto = str(block.get("protocol", "")).lower()
        ports = block.get("ports") or []
        if isinstance(ports, (str, int)):
            ports = [str(ports)]
        port_set = {str(p).strip().lower() for p in ports}

        if check_all:
            if proto in ("all", "-1") or (proto in ("tcp", "udp") and not port_set):
                return True, "Firewall allows unrestricted traffic from 0.0.0.0/0"
        else:
            if proto in ("all", "-1"):
                return True, f"Port {target_port} exposed via wildcard protocol '{proto}'"
            if str(target_port) in port_set:
                return True, f"Port {target_port} is allowed from 0.0.0.0/0"
            for p_range in port_set:
                if "-" in p_range:
                    parts = p_range.split("-")
                    try:
                        low, high = int(parts[0]), int(parts[1])
                        if low <= target_port <= high:
                            return (
                                True,
                                f"Port {target_port} in allowed range {p_range} from 0.0.0.0/0",
                            )
                    except ValueError:
                        pass

    return False, ""


class StoragePublicIAMRule(SecurityRule):
    """IG-GCP-001: Detect Cloud Storage IAM bindings granting public access."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-001",
            title="Cloud Storage Public IAM Access",
            description="Detect Cloud Storage IAM bindings that grant access to allUsers or allAuthenticatedUsers.",
            provider=Provider.GCP,
            severity=Severity.CRITICAL,
            resource_types=["storage_iam_binding"],
            rationale="Granting storage access to allUsers exposes bucket data anonymously to the internet.",
            remediation="Remove allUsers and allAuthenticatedUsers from Cloud Storage IAM members.",
            references=["https://cloud.google.com/storage/docs/access-control/iam"],
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
        members = props.get("members") or props.get("member") or []
        if isinstance(members, str):
            members = [members]

        lower_members = {str(m).strip().lower() for m in members}
        public_found = lower_members & PUBLIC_GCP_MEMBERS

        if public_found:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence=f"Storage IAM grant includes public member: {', '.join(public_found)}",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="Storage IAM binding does not grant access to public members",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class FirewallSSHRule(SecurityRule):
    """IG-GCP-002: Detect firewall rules that expose SSH to the internet."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-002",
            title="GCP Firewall SSH Exposed to Internet (Port 22)",
            description="Detect Google Cloud VPC firewall ingress rules permitting port 22 from 0.0.0.0/0.",
            provider=Provider.GCP,
            severity=Severity.CRITICAL,
            resource_types=["firewall_rule"],
            rationale="Internet-accessible SSH allows unauthorized actors to attempt brute force attacks.",
            remediation="Restrict source_ranges to corporate networks or use GCP Identity-Aware Proxy (IAP).",
            references=["https://cloud.google.com/firewall/docs/firewalls-overview"],
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
        direction = str(props.get("direction", "INGRESS")).upper()
        if direction != "INGRESS":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Rule is egress, not ingress",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        src_ranges = props.get("source_ranges") or []
        if isinstance(src_ranges, str):
            src_ranges = [src_ranges]

        allow_blocks = props.get("allow") or []
        if isinstance(allow_blocks, dict):
            allow_blocks = [allow_blocks]

        violation, ev = _check_gcp_firewall_ports(allow_blocks, src_ranges, 22)
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
            evidence="Firewall ingress does not allow SSH (port 22) from 0.0.0.0/0",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class FirewallRDPRule(SecurityRule):
    """IG-GCP-003: Detect firewall rules that expose RDP to the internet."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-003",
            title="GCP Firewall RDP Exposed to Internet (Port 3389)",
            description="Detect Google Cloud VPC firewall ingress rules permitting port 3389 from 0.0.0.0/0.",
            provider=Provider.GCP,
            severity=Severity.CRITICAL,
            resource_types=["firewall_rule"],
            rationale="Unrestricted RDP creates critical exposure to Windows exploits and ransomware.",
            remediation="Restrict source_ranges or use GCP IAP TCP forwarding for RDP access.",
            references=["https://cloud.google.com/firewall/docs/firewalls-overview"],
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
        direction = str(props.get("direction", "INGRESS")).upper()
        if direction != "INGRESS":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Rule is egress, not ingress",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        src_ranges = props.get("source_ranges") or []
        if isinstance(src_ranges, str):
            src_ranges = [src_ranges]

        allow_blocks = props.get("allow") or []
        if isinstance(allow_blocks, dict):
            allow_blocks = [allow_blocks]

        violation, ev = _check_gcp_firewall_ports(allow_blocks, src_ranges, 3389)
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
            evidence="Firewall ingress does not allow RDP (port 3389) from 0.0.0.0/0",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class FirewallPermissiveRule(SecurityRule):
    """IG-GCP-004: Detect overly broad firewall ingress rules."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-004",
            title="GCP Firewall Overly Permissive Ingress",
            description="Detect firewall ingress rules allowing all traffic or all protocols from 0.0.0.0/0.",
            provider=Provider.GCP,
            severity=Severity.HIGH,
            resource_types=["firewall_rule"],
            rationale="Unrestricted firewall rules expose internal instances across all ports to attackers.",
            remediation="Specify explicit protocols, destination port numbers, and restricted source IP ranges.",
            references=["https://cloud.google.com/firewall/docs/firewalls-overview"],
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
        direction = str(props.get("direction", "INGRESS")).upper()
        if direction != "INGRESS":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Rule is egress, not ingress",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        src_ranges = props.get("source_ranges") or []
        if isinstance(src_ranges, str):
            src_ranges = [src_ranges]

        allow_blocks = props.get("allow") or []
        if isinstance(allow_blocks, dict):
            allow_blocks = [allow_blocks]

        violation, ev = _check_gcp_firewall_ports(allow_blocks, src_ranges, 0, check_all=True)
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
            evidence="Firewall does not allow unrestricted all-protocol ingress from 0.0.0.0/0",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class StorageUniformAccessRule(SecurityRule):
    """IG-GCP-005: Detect storage buckets without uniform bucket-level access enabled."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-005",
            title="Cloud Storage Uniform Bucket-Level Access Disabled",
            description="Detect Cloud Storage buckets where uniform bucket-level access is not enabled.",
            provider=Provider.GCP,
            severity=Severity.MEDIUM,
            resource_types=["storage_bucket"],
            rationale="Fine-grained ACLs can inadvertently expose individual objects; uniform access enforces consistent IAM policies.",
            remediation="Set uniform_bucket_level_access = true.",
            references=["https://cloud.google.com/storage/docs/uniform-bucket-level-access"],
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
        val = props.get("uniform_bucket_level_access")
        if val is True or str(val).lower() == "true":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Uniform bucket-level access is enabled",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.FAIL,
            severity=meta.severity,
            evidence="Uniform bucket-level access is disabled or not explicitly enabled",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class StoragePublicAccessPreventionRule(SecurityRule):
    """IG-GCP-006: Detect storage buckets without public access prevention enforced."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-006",
            title="Cloud Storage Public Access Prevention Missing",
            description="Detect Cloud Storage buckets where public access prevention is not set to 'enforced'.",
            provider=Provider.GCP,
            severity=Severity.MEDIUM,
            resource_types=["storage_bucket"],
            rationale="Public access prevention prevents buckets and their data from being exposed to allUsers.",
            remediation="Set public_access_prevention = 'enforced'.",
            references=["https://cloud.google.com/storage/docs/public-access-prevention"],
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
        val = props.get("public_access_prevention")
        if str(val).lower() == "enforced":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.PASS,
                severity=meta.severity,
                evidence="Public access prevention is set to 'enforced'",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.FAIL,
            severity=meta.severity,
            evidence="Public access prevention is not set to 'enforced'",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class ProjectIAMBroadGrantsRule(SecurityRule):
    """IG-GCP-007: Detect overly broad IAM grants on Google Cloud projects."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-GCP-007",
            title="Overly Broad GCP Project IAM Role Grants",
            description="Detect project IAM bindings granting broad or primitive roles to public principals.",
            provider=Provider.GCP,
            severity=Severity.HIGH,
            resource_types=["project_iam_binding"],
            rationale="Granting primitive roles (Editor, Owner) to public users compromises the entire GCP project.",
            remediation="Remove public members and grant scoped predefined roles to specific identities.",
            references=["https://cloud.google.com/iam/docs/understanding-roles"],
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
        members = props.get("members") or props.get("member") or []
        if isinstance(members, str):
            members = [members]

        lower_members = {str(m).strip().lower() for m in members}
        has_public = bool(lower_members & PUBLIC_GCP_MEMBERS)

        role = str(props.get("role", "")).lower()
        is_broad_role = (
            role in ("roles/owner", "roles/editor", "roles/viewer", "roles/admin")
            or "admin" in role
        )

        if has_public and is_broad_role:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence=f"Project IAM grants broad role '{role}' to public principal: {', '.join(lower_members & PUBLIC_GCP_MEMBERS)}",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="Project IAM binding does not grant broad roles to public users",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )
