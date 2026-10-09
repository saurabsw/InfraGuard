"""AWS Security Rules (IG-AWS-001 to IG-AWS-010, IG-IAM-001)."""

from __future__ import annotations

import json
import re
from typing import Any

from app.core.constants import EvaluationStatus, Provider, Severity
from app.engine.rule_base import EvaluationResult, RuleMetadata, SecurityRule
from app.schemas.resource import NormalizedResource


def _extract_statements(policy_val: Any) -> list[dict[str, Any]]:
    """Extract policy statements from string JSON, dict, or HCL jsonencode structure."""
    if isinstance(policy_val, str):
        s = policy_val.strip()
        # Direct JSON decode
        try:
            policy_val = json.loads(s)
        except Exception:
            # Handle HCL ${jsonencode(...)} wrapper or HCL object syntax
            candidate = s
            if candidate.startswith("${jsonencode(") and candidate.endswith(")}"):
                candidate = candidate[13:-2].strip()
            # Replace HCL Identifier = Value with "Identifier": Value
            json_like = re.sub(r"([a-zA-Z0-9_]+)\s*=", r'"\1":', candidate)
            try:
                policy_val = json.loads(json_like)
            except Exception:
                # Regex statement extractor fallback
                stmts: list[dict[str, Any]] = []
                # Look for statements
                eff_match = re.search(r'Effect\s*[=:]\s*"?([a-zA-Z]+)"?', s, re.IGNORECASE)
                princ_match = re.search(r'Principal\s*[=:]\s*"?([^,\n\}\]]+)"?', s, re.IGNORECASE)
                act_matches = re.findall(r'"([a-zA-Z0-9_:*]+)"', s)
                if eff_match:
                    stmts.append(
                        {
                            "Effect": eff_match.group(1),
                            "Principal": princ_match.group(1).strip() if princ_match else "",
                            "Action": act_matches,
                            "Resource": "*",
                        }
                    )
                return stmts

    if isinstance(policy_val, dict):
        stmts = policy_val.get("Statement") or policy_val.get("statement") or []
        if isinstance(stmts, dict):
            return [stmts]
        elif isinstance(stmts, list):
            return [s for s in stmts if isinstance(s, dict)]
    elif isinstance(policy_val, list):
        out = []
        for item in policy_val:
            if isinstance(item, dict):
                out.append(item)
        return out
    return []


def _is_wildcard_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws_p = principal.get("AWS") or principal.get("aws")
        if aws_p == "*" or (isinstance(aws_p, list) and "*" in aws_p):
            return True
    return bool(isinstance(principal, list) and "*" in principal)


def _matches_action(actions: Any, targets: set[str]) -> bool:
    if isinstance(actions, str):
        actions = [actions]
    if not isinstance(actions, list):
        return False
    for a in actions:
        if not isinstance(a, str):
            continue
        low = a.lower()
        if low == "*" or low == "s3:*":
            return True
        for t in targets:
            if low == t.lower():
                return True
    return False


class S3PublicReadRule(SecurityRule):
    """IG-AWS-001: S3 Public Read Access."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-001",
            title="S3 Public Read Access",
            description="Detect S3 bucket policies that explicitly permit public read access.",
            provider=Provider.AWS,
            severity=Severity.CRITICAL,
            resource_types=["s3_bucket_policy"],
            rationale="Public read access allows anyone on the internet to read sensitive data.",
            remediation="Remove public principals from bucket policy statements granting read actions.",
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
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

        policy_raw = resource.properties.get("policy") or resource.properties.get("PolicyDocument")
        if not policy_raw:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.NOT_EVALUATED,
                severity=meta.severity,
                evidence="Bucket policy contains no policy document or definition",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        statements = _extract_statements(policy_raw)
        if not statements:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.NOT_EVALUATED,
                severity=meta.severity,
                evidence="Could not extract statements from policy document",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        read_actions = {"s3:getobject", "s3:get*"}
        for stmt in statements:
            effect = stmt.get("Effect") or stmt.get("effect")
            if effect == "Allow" and _is_wildcard_principal(
                stmt.get("Principal") or stmt.get("principal")
            ):
                actions = stmt.get("Action") or stmt.get("action")
                if _matches_action(actions, read_actions):
                    return EvaluationResult(
                        rule_id=meta.rule_id,
                        resource_id=resource.resource_id,
                        resource_type=resource.resource_type,
                        status=EvaluationStatus.FAIL,
                        severity=meta.severity,
                        evidence="Bucket policy grants public read permissions to '*'",
                        remediation=meta.remediation,
                        source_file=resource.source_file,
                    )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="Bucket policy does not permit public read access",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class S3PublicWriteRule(SecurityRule):
    """IG-AWS-002: S3 Public Write Access."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-002",
            title="S3 Public Write Access",
            description="Detect S3 bucket policies that permit public write access.",
            provider=Provider.AWS,
            severity=Severity.CRITICAL,
            resource_types=["s3_bucket_policy"],
            rationale="Public write access allows attackers to upload malicious content or overwrite data.",
            remediation="Remove public principals from bucket policy statements granting write actions.",
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
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

        policy_raw = resource.properties.get("policy") or resource.properties.get("PolicyDocument")
        if not policy_raw:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.NOT_EVALUATED,
                severity=meta.severity,
                evidence="Bucket policy contains no policy document or definition",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        statements = _extract_statements(policy_raw)
        if not statements:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.NOT_EVALUATED,
                severity=meta.severity,
                evidence="Could not extract statements from policy document",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        write_actions = {"s3:putobject", "s3:put*"}
        for stmt in statements:
            effect = stmt.get("Effect") or stmt.get("effect")
            if effect == "Allow" and _is_wildcard_principal(
                stmt.get("Principal") or stmt.get("principal")
            ):
                actions = stmt.get("Action") or stmt.get("action")
                if _matches_action(actions, write_actions):
                    return EvaluationResult(
                        rule_id=meta.rule_id,
                        resource_id=resource.resource_id,
                        resource_type=resource.resource_type,
                        status=EvaluationStatus.FAIL,
                        severity=meta.severity,
                        evidence="Bucket policy grants public write permissions to '*'",
                        remediation=meta.remediation,
                        source_file=resource.source_file,
                    )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="Bucket policy does not permit public write access",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class S3BlockPublicAccessRule(SecurityRule):
    """IG-AWS-003: S3 Block Public Access Missing or Disabled."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-003",
            title="S3 Block Public Access Missing or Disabled",
            description="Detect missing or explicitly disabled S3 Block Public Access settings.",
            provider=Provider.AWS,
            severity=Severity.HIGH,
            resource_types=["s3_public_access_block"],
            rationale="S3 Block Public Access provides centralized protection against public exposure.",
            remediation="Enable all four block public access settings (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets).",
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
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
        required_keys = [
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ]

        missing_or_disabled = []
        for k in required_keys:
            val = props.get(k)
            # Accept True or "true"
            if val is not True and str(val).lower() != "true":
                missing_or_disabled.append(k)

        if missing_or_disabled:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence=f"Block public access settings not fully enabled: {', '.join(missing_or_disabled)}",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="All four S3 block public access protections are explicitly enabled",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


def _check_ingress_ports(
    ingress_list: list[dict[str, Any]], target_port: int, check_all: bool = False
) -> tuple[bool, str]:
    """Helper to check security group ingress rules for open ports."""
    open_cidrs = {"0.0.0.0/0", "::/0"}

    for rule in ingress_list:
        if not isinstance(rule, dict):
            continue

        cidrs = rule.get("cidr_blocks") or rule.get("CidrIp") or []
        if isinstance(cidrs, str):
            cidrs = [cidrs]
        ipv6_cidrs = rule.get("ipv6_cidr_blocks") or rule.get("CidrIpv6") or []
        if isinstance(ipv6_cidrs, str):
            ipv6_cidrs = [ipv6_cidrs]

        all_cidrs = set(cidrs) | set(ipv6_cidrs)
        is_open = bool(all_cidrs & open_cidrs)

        if not is_open:
            continue

        from_p = rule.get("from_port") or rule.get("FromPort")
        to_p = rule.get("to_port") or rule.get("ToPort")
        proto = rule.get("protocol") or rule.get("IpProtocol")

        if check_all:
            # Overly permissive: protocol is -1 or ports are 0-65535 or 0-0
            if proto in ("-1", -1, "all") or (from_p == 0 and to_p in (0, 65535)):
                return True, "Ingress allows all traffic from 0.0.0.0/0 or ::/0"
        else:
            if from_p is not None and to_p is not None:
                try:
                    f = int(from_p)
                    t = int(to_p)
                    if f <= target_port <= t:
                        return (
                            True,
                            f"Port {target_port} is exposed to internet (0.0.0.0/0 or ::/0)",
                        )
                except (ValueError, TypeError):
                    pass
            elif proto in ("-1", -1, "all"):
                return True, f"Port {target_port} is exposed via wildcard protocol (-1)"

    return False, ""


class SecurityGroupSSHRule(SecurityRule):
    """IG-AWS-004: Detect internet-wide SSH ingress on port 22."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-004",
            title="Internet-Wide SSH Ingress (Port 22)",
            description="Detect security groups allowing unrestricted ingress on port 22.",
            provider=Provider.AWS,
            severity=Severity.CRITICAL,
            resource_types=["security_group", "security_group_rule"],
            rationale="Unrestricted SSH exposes instances to brute-force and remote exploit attacks.",
            remediation="Restrict SSH ingress to specific corporate CIDRs or use AWS Systems Manager Session Manager.",
            references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"],
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
        # Could be security group with ingress list, or standalone security_group_rule
        ingress_list = props.get("ingress") or props.get("SecurityGroupIngress") or []
        if isinstance(ingress_list, dict):
            ingress_list = [ingress_list]
        if not ingress_list and resource.resource_type == "security_group_rule":
            ingress_list = [props]

        violation, ev = _check_ingress_ports(ingress_list, 22)
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
            evidence="SSH port 22 is not exposed to 0.0.0.0/0",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class SecurityGroupRDPRule(SecurityRule):
    """IG-AWS-005: Detect internet-wide RDP ingress on port 3389."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-005",
            title="Internet-Wide RDP Ingress (Port 3389)",
            description="Detect security groups allowing unrestricted ingress on port 3389.",
            provider=Provider.AWS,
            severity=Severity.CRITICAL,
            resource_types=["security_group", "security_group_rule"],
            rationale="Unrestricted RDP exposes instances to brute-force and remote desktop vulnerabilities.",
            remediation="Restrict RDP ingress to specific trusted CIDRs or bastion hosts.",
            references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"],
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
        ingress_list = props.get("ingress") or props.get("SecurityGroupIngress") or []
        if isinstance(ingress_list, dict):
            ingress_list = [ingress_list]
        if not ingress_list and resource.resource_type == "security_group_rule":
            ingress_list = [props]

        violation, ev = _check_ingress_ports(ingress_list, 3389)
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
            evidence="RDP port 3389 is not exposed to 0.0.0.0/0",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class SecurityGroupPermissiveRule(SecurityRule):
    """IG-AWS-006: Detect overly permissive inbound network rules."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-006",
            title="Overly Permissive Inbound Network Rules",
            description="Detect ingress rules permitting unrestricted traffic on all protocols or all ports.",
            provider=Provider.AWS,
            severity=Severity.HIGH,
            resource_types=["security_group", "security_group_rule"],
            rationale="Unrestricted inbound traffic negates network segmentation and firewall defenses.",
            remediation="Specify precise protocols, port ranges, and restricted CIDR prefixes.",
            references=["https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html"],
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
        ingress_list = props.get("ingress") or props.get("SecurityGroupIngress") or []
        if isinstance(ingress_list, dict):
            ingress_list = [ingress_list]
        if not ingress_list and resource.resource_type == "security_group_rule":
            ingress_list = [props]

        violation, ev = _check_ingress_ports(ingress_list, 0, check_all=True)
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
            evidence="Security group does not allow unrestricted all-protocol ingress",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class RDSPublicAccessRule(SecurityRule):
    """IG-AWS-007: Detect RDS resources configured for public accessibility."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-007",
            title="RDS Instance Publicly Accessible",
            description="Detect RDS instances configured with public accessibility enabled.",
            provider=Provider.AWS,
            severity=Severity.CRITICAL,
            resource_types=["rds_instance"],
            rationale="Databases should reside in private subnets and never be directly accessible from the internet.",
            remediation="Set publicly_accessible = false on the RDS instance resource.",
            references=[
                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.RDSSecurityGroups.html"
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
        val = props.get("publicly_accessible")
        if val is None:
            val = props.get("PubliclyAccessible")

        if val is True or str(val).lower() == "true":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="RDS instance is configured with publicly_accessible = true",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="RDS instance is not publicly accessible",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class RDSStorageEncryptionRule(SecurityRule):
    """IG-AWS-008: Detect disabled RDS storage encryption."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-008",
            title="RDS Storage Encryption Disabled",
            description="Detect RDS instances where storage encryption is explicitly disabled or omitted.",
            provider=Provider.AWS,
            severity=Severity.HIGH,
            resource_types=["rds_instance"],
            rationale="Unencrypted database storage risks data exposure if underlying disks are compromised.",
            remediation="Set storage_encrypted = true on the RDS instance.",
            references=[
                "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
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
        val = props.get("storage_encrypted")
        if val is None:
            val = props.get("StorageEncrypted")

        if val is False or str(val).lower() == "false":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="RDS storage encryption is explicitly set to false",
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
                evidence="RDS storage encryption is enabled",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.NOT_EVALUATED,
            severity=meta.severity,
            evidence="Storage encryption property is omitted or indeterminate",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class EBSVolumeEncryptionRule(SecurityRule):
    """IG-AWS-009: Detect unencrypted EBS volumes."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-009",
            title="EBS Volume Encryption Disabled",
            description="Detect EBS volumes where encryption is explicitly disabled or omitted.",
            provider=Provider.AWS,
            severity=Severity.HIGH,
            resource_types=["ebs_volume"],
            rationale="Unencrypted EBS volumes risk sensitive data exposure at rest.",
            remediation="Set encrypted = true on the EBS volume.",
            references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
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
        val = props.get("encrypted")
        if val is None:
            val = props.get("Encrypted")

        if val is False or str(val).lower() == "false":
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="EBS volume encryption is explicitly disabled",
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
                evidence="EBS volume encryption is enabled",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.NOT_EVALUATED,
            severity=meta.severity,
            evidence="EBS volume encryption setting is omitted or indeterminate",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class IAMWildcardPermissionsRule(SecurityRule):
    """IG-IAM-001: Detect overly broad IAM permissions."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-IAM-001",
            title="Overly Broad IAM Permissions (Wildcard Action & Resource)",
            description="Detect IAM policies granting wildcard actions and resources in Allow statements.",
            provider=Provider.AWS,
            severity=Severity.CRITICAL,
            resource_types=["iam_policy", "iam_role_policy", "iam_policy_document"],
            rationale="Wildcard permissions grant full administrative privileges, violating least privilege.",
            remediation="Specify explicit IAM actions and scope resources to specific ARNs.",
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
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
        policy_raw = props.get("policy") or props.get("PolicyDocument") or props.get("statement")

        statements = _extract_statements(policy_raw or props)
        if not statements:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.NOT_EVALUATED,
                severity=meta.severity,
                evidence="IAM policy has no parseable statement block",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        for stmt in statements:
            effect = stmt.get("Effect") or stmt.get("effect")
            if effect == "Allow":
                actions = stmt.get("Action") or stmt.get("actions") or stmt.get("action")
                resources = stmt.get("Resource") or stmt.get("resources") or stmt.get("resource")

                act_wild = actions == "*" or (isinstance(actions, list) and "*" in actions)
                res_wild = resources == "*" or (isinstance(resources, list) and "*" in resources)

                if act_wild and res_wild:
                    return EvaluationResult(
                        rule_id=meta.rule_id,
                        resource_id=resource.resource_id,
                        resource_type=resource.resource_type,
                        status=EvaluationStatus.FAIL,
                        severity=meta.severity,
                        evidence="Policy statement grants Effect: Allow with Action: '*' and Resource: '*'",
                        remediation=meta.remediation,
                        source_file=resource.source_file,
                    )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="IAM policy does not grant full admin wildcard permissions",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )


class S3BucketLoggingRule(SecurityRule):
    """IG-AWS-010: Detect missing explicit S3 server access logging."""

    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="IG-AWS-010",
            title="S3 Bucket Server Access Logging Disabled",
            description="Detect S3 buckets without explicit access logging configured.",
            provider=Provider.AWS,
            severity=Severity.MEDIUM,
            resource_types=["s3_bucket", "s3_bucket_logging"],
            rationale="Server access logs provide audit trails for security investigations and compliance.",
            remediation="Configure aws_s3_bucket_logging or define a logging block with a target bucket.",
            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"],
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

        if resource.resource_type == "s3_bucket_logging":
            target = resource.properties.get("target_bucket") or resource.properties.get(
                "TargetBucket"
            )
            if target:
                return EvaluationResult(
                    rule_id=meta.rule_id,
                    resource_id=resource.resource_id,
                    resource_type=resource.resource_type,
                    status=EvaluationStatus.PASS,
                    severity=meta.severity,
                    evidence="S3 bucket logging is configured with a target bucket",
                    remediation=meta.remediation,
                    source_file=resource.source_file,
                )

        # For s3_bucket: check inline logging block
        logging_cfg = resource.properties.get("logging") or resource.properties.get(
            "LoggingConfiguration"
        )
        if not logging_cfg:
            return EvaluationResult(
                rule_id=meta.rule_id,
                resource_id=resource.resource_id,
                resource_type=resource.resource_type,
                status=EvaluationStatus.FAIL,
                severity=meta.severity,
                evidence="S3 bucket does not have server access logging configured",
                remediation=meta.remediation,
                source_file=resource.source_file,
            )

        return EvaluationResult(
            rule_id=meta.rule_id,
            resource_id=resource.resource_id,
            resource_type=resource.resource_type,
            status=EvaluationStatus.PASS,
            severity=meta.severity,
            evidence="S3 bucket server access logging is enabled",
            remediation=meta.remediation,
            source_file=resource.source_file,
        )
