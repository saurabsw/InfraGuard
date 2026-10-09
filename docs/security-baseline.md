# InfraGuard — Security Baseline Documentation

> **Version:** 1.0.0  
> **Document Status:** Authoritative Security Baseline  
> **Standard:** Derived from CIS Benchmarks (AWS, Azure, GCP), AWS FSBP, Azure Security Benchmark v3, and GCP Security Foundations 2.0.

InfraGuard implements a deterministic, multi-cloud security guardrail baseline for static infrastructure-as-code analysis.

---

## 1. Rule Summary Matrix

| Rule ID | Provider | Title | Severity | Penalty | Canonical Resource | Industry Benchmark |
|---|---|---|---|---|---|---|
| **IG-AWS-001** | AWS | S3 Public Read Access | Critical | 25 | `s3_bucket_policy` | CIS AWS 2.1.5 |
| **IG-AWS-002** | AWS | S3 Public Write Access | Critical | 25 | `s3_bucket_policy` | CIS AWS 2.1.5 |
| **IG-AWS-003** | AWS | S3 Block Public Access Disabled/Missing | High | 15 | `s3_public_access_block` | AWS FSBP S3.1 |
| **IG-AWS-004** | AWS | SSH Ingress Exposed to Internet (Port 22) | Critical | 25 | `security_group`, `security_group_rule` | CIS AWS 5.2 |
| **IG-AWS-005** | AWS | RDP Ingress Exposed to Internet (Port 3389) | Critical | 25 | `security_group`, `security_group_rule` | CIS AWS 5.3 |
| **IG-AWS-006** | AWS | Overly Permissive Inbound Network Rules | High | 15 | `security_group`, `security_group_rule` | CIS AWS 5.1 |
| **IG-AWS-007** | AWS | RDS Instance Publicly Accessible | Critical | 25 | `rds_instance` | CIS AWS 2.3.1 |
| **IG-AWS-008** | AWS | RDS Storage Encryption Disabled | High | 15 | `rds_instance` | CIS AWS 2.3.2 |
| **IG-AWS-009** | AWS | EBS Volume Encryption Disabled | High | 15 | `ebs_volume` | CIS AWS 2.2.1 |
| **IG-IAM-001** | AWS | Overly Broad IAM Permissions (Wildcard) | Critical | 25 | `iam_policy`, `iam_role_policy` | CIS AWS 1.16 |
| **IG-AWS-010** | AWS | S3 Bucket Server Access Logging Disabled | Medium | 7 | `s3_bucket`, `s3_bucket_logging` | CIS AWS 2.1.3 |
| **IG-AZ-001** | Azure | Storage Account Allows Public Blob Access | High | 15 | `storage_account` | CIS Azure 5.1.1 |
| **IG-AZ-002** | Azure | NSG Inbound SSH Exposed to Internet (Port 22) | Critical | 25 | `network_security_group`, `network_security_rule` | CIS Azure 6.1 |
| **IG-AZ-003** | Azure | NSG Inbound RDP Exposed to Internet (Port 3389) | Critical | 25 | `network_security_group`, `network_security_rule` | CIS Azure 6.2 |
| **IG-AZ-004** | Azure | Storage Account Secure Transfer Disabled | High | 15 | `storage_account` | CIS Azure 5.1.2 |
| **IG-AZ-005** | Azure | Storage Account Infrastructure Encryption Missing | Medium | 7 | `storage_account` | Azure Benchmark DP-4 |
| **IG-AZ-006** | Azure | NSG Overly Permissive Inbound Traffic | High | 15 | `network_security_group`, `network_security_rule` | CIS Azure 6.3 |
| **IG-AZ-007** | Azure | Database Public Network Access Enabled | Critical | 25 | `sql_server`, `postgresql_server`, `mysql_server` | CIS Azure 4.1.1 |
| **IG-GCP-001** | GCP | Cloud Storage Public IAM Access | Critical | 25 | `storage_iam_binding` | CIS GCP 5.1 |
| **IG-GCP-002** | GCP | Firewall SSH Exposed to Internet (Port 22) | Critical | 25 | `firewall_rule` | CIS GCP 3.6 |
| **IG-GCP-003** | GCP | Firewall RDP Exposed to Internet (Port 3389) | Critical | 25 | `firewall_rule` | CIS GCP 3.7 |
| **IG-GCP-004** | GCP | Firewall Overly Permissive Ingress | High | 15 | `firewall_rule` | CIS GCP 3.8 |
| **IG-GCP-005** | GCP | Cloud Storage Uniform Bucket Access Disabled | Medium | 7 | `storage_bucket` | CIS GCP 5.2 |
| **IG-GCP-006** | GCP | Cloud Storage Public Access Prevention Missing | Medium | 7 | `storage_bucket` | GCP Security Foundation |
| **IG-GCP-007** | GCP | Overly Broad GCP Project IAM Role Grants | High | 15 | `project_iam_binding` | CIS GCP 1.4 |

---

## 2. Evaluation Status Semantics

Per PRD §7, every resource evaluation emits an explicit status:

- **`PASS`**: Configuration explicitly satisfies security controls.
- **`FAIL`**: Security violation detected with actionable code evidence and remediation.
- **`NOT_EVALUATED`**: Attributes omitted, indeterminate, or unresolvable static references.
- **`UNSUPPORTED`**: The resource type is outside the supported MVP scope. **Never silently skipped or falsely marked as secure.**

---

## 3. Risk Scoring & Classification

- **Penalty Deduction Formula**:
  $$\text{Risk Score} = \max\left(0, 100 - \sum \text{Severities}\right)$$
- **Penalties by Severity**:
  - `CRITICAL`: 25 points
  - `HIGH`: 15 points
  - `MEDIUM`: 7 points
  - `LOW`: 2 points
- **Risk Bands**:
  - `90 - 100`: **LOW**
  - `70 - 89`: **MODERATE**
  - `40 - 69`: **HIGH**
  - `0 - 39`: **CRITICAL**

---

## 4. Detailed Rule Definitions & Remediation

### AWS Rules
- **IG-AWS-001 (S3 Public Read)**: Detects bucket policies granting `Principal: "*"` or `Action: ["s3:GetObject"]` to all users. Remediation: Restrict Principal to authenticated IAM entities or VPC endpoints.
- **IG-AWS-002 (S3 Public Write)**: Detects public `PutObject` or wildcard actions allowing arbitrary write access. Remediation: Disallow anonymous writes to S3.
- **IG-AWS-003 (S3 Block Public Access)**: Flags buckets missing `aws_s3_bucket_public_access_block` or having any block flags set to `false`. Remediation: Enable all 4 block public access settings.
- **IG-AWS-004 (SSH Ingress)**: Flags security groups with ingress from `0.0.0.0/0` on port 22. Remediation: Restrict SSH to specific trusted CIDRs or use AWS Systems Manager Session Manager.
- **IG-AWS-005 (RDP Ingress)**: Flags security groups with ingress from `0.0.0.0/0` on port 3389. Remediation: Restrict RDP to authorized corporate VPN blocks.
- **IG-AWS-006 (Overly Permissive Ingress)**: Flags rules opening all protocols (`-1`) or all ports (`0-65535`) to `0.0.0.0/0`. Remediation: Restrict ingress rules to explicitly required ports and protocols.
- **IG-AWS-007 (RDS Public Access)**: Flags RDS instances with `publicly_accessible = true`. Remediation: Place RDS instances in private subnets with `publicly_accessible = false`.
- **IG-AWS-008 (RDS Storage Encryption)**: Flags RDS instances with `storage_encrypted = false`. Remediation: Set `storage_encrypted = true` with AWS KMS CMK or default key.
- **IG-AWS-009 (EBS Volume Encryption)**: Flags unencrypted EBS volumes (`encrypted = false`). Remediation: Enable EBS encryption at rest.
- **IG-IAM-001 (Overly Broad IAM Permissions)**: Flags IAM policies containing `"Action": "*"` and `"Resource": "*"`. Remediation: Adhere to least-privilege by specifying explicit API actions and scoped ARNs.
- **IG-AWS-010 (S3 Bucket Logging)**: Flags S3 buckets without server access logging enabled. Remediation: Attach an `aws_s3_bucket_logging` resource to forward logs to a centralized audit bucket.

### Azure Rules
- **IG-AZ-001 (Public Blob Access)**: Flags Azure storage accounts where `allow_nested_items_to_be_public` is true. Remediation: Set `allow_nested_items_to_be_public = false`.
- **IG-AZ-002 (NSG SSH Ingress)**: Flags NSG rules permitting port 22 from `*` or `Internet`. Remediation: Restrict SSH ingress or utilize Azure Bastion.
- **IG-AZ-003 (NSG RDP Ingress)**: Flags NSG rules permitting port 3389 from `*` or `Internet`. Remediation: Restrict RDP to internal virtual networks.
- **IG-AZ-004 (Secure Transfer)**: Flags storage accounts with `enable_https_traffic_only = false`. Remediation: Enforce HTTPS-only access for Azure Storage.
- **IG-AZ-005 (Infrastructure Encryption)**: Flags storage accounts missing double-encryption for high-compliance workloads. Remediation: Set `infrastructure_encryption_enabled = true`.
- **IG-AZ-006 (NSG Permissive Inbound)**: Flags rules opening `*` destination ports to `*` source CIDRs with `Allow` action. Remediation: Scope NSG rules to specific application destination ports.
- **IG-AZ-007 (Database Public Network Access)**: Flags Azure SQL / PostgreSQL servers with `public_network_access_enabled = true`. Remediation: Set `public_network_access_enabled = false` and use Private Endpoints.

### GCP Rules
- **IG-GCP-001 (Cloud Storage Public IAM)**: Flags buckets granting roles to `allUsers` or `allAuthenticatedUsers`. Remediation: Remove public members from IAM bindings.
- **IG-GCP-002 (Firewall SSH)**: Flags GCP firewall rules allowing tcp:22 from `0.0.0.0/0`. Remediation: Restrict source ranges or use Identity-Aware Proxy (IAP).
- **IG-GCP-003 (Firewall RDP)**: Flags GCP firewall rules allowing tcp:3389 from `0.0.0.0/0`. Remediation: Restrict source ranges.
- **IG-GCP-004 (Firewall Permissive)**: Flags firewall rules allowing all protocols and ports from `0.0.0.0/0`. Remediation: Explicitly define allowed ports and protocols.
- **IG-GCP-005 (Uniform Bucket Access)**: Flags storage buckets with `uniform_bucket_level_access = false`. Remediation: Enable uniform bucket-level access.
- **IG-GCP-006 (Public Access Prevention)**: Flags storage buckets without `public_access_prevention = "enforced"`. Remediation: Enforce public access prevention.
- **IG-GCP-007 (Project IAM Broad Roles)**: Flags project IAM bindings assigning `roles/owner` or `roles/editor` to public identities or broad groups. Remediation: Grant granular predefined or custom IAM roles.
