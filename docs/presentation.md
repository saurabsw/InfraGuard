# InfraGuard — Multi-Cloud IaC Security Guardrail Auditor
## Executive Presentation & Architecture Briefing

---

## Slide 1: Title & Executive Vision
# InfraGuard
### API-First Multi-Cloud Infrastructure Security Guardrail Auditor
**Version:** 1.0.0 (MVP Release)  
**Presenter:** Security Architecture Lead  
**Tech Stack:** FastAPI | Streamlit | SQLite (WAL) | python-hcl2 | PyYAML | Plotly

> *"Empowering DevOps and Security teams with deterministic, offline static analysis of cloud infrastructure templates across AWS, Azure, and GCP."*

---

## Slide 2: The Problem
### Cloud Security Gaps in the Pre-Deployment Lifecycle
- **Shift-Left Blindspots**: Security misconfigurations (e.g., public S3 buckets, exposed SSH/RDP ports, wildcard IAM privileges) frequently reach production.
- **Multi-Cloud Complexity**: Inconsistent security definitions between AWS CloudFormation, AWS Terraform, Azure Resource Manager/Terraform, and GCP Terraform.
- **Nondeterministic / Opaque Tooling**: Traditional scanners often obscure risk calculations, suffer from network latency contacting live cloud APIs, or drop unknown configurations silently.
- **Architectural Coupling**: Heavy monolithic security tools that bundle UI and auditing logic, preventing easy integration into CI/CD pipelines.

---

## Slide 3: The InfraGuard Solution
### Deterministic, API-First Multi-Cloud Auditing
1. **True API-First Architecture**: Standalone FastAPI REST backend. Completely usable through CLI, CI/CD, and HTTP curl requests.
2. **Decoupled Frontend**: Pure Streamlit HTTP consumer that communicates solely via published REST endpoints.
3. **Multi-Cloud Guardrail Baseline**: 25 enterprise security rules across AWS (11), Azure (7), and GCP (7).
4. **Deterministic & Explainable Scoring**: Mathematical deduction from a 100-point ceiling with standardized risk bands (Low, Moderate, High, Critical).
5. **Zero Cloud Dependencies**: 100% offline static analysis. Never runs uploaded code, never requires AWS/Azure/GCP credentials.

---

## Slide 4: System Architecture
### Clean Layered Decoupling

```
┌─────────────────────────────────────────────────────────────┐
│             Streamlit Web Dashboard (Port 8501)             │
│   (Metrics, Severity Donut Charts, Findings, CSV/JSON)      │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / REST API Calls
┌──────────────────────────────▼──────────────────────────────┐
│                  FastAPI Backend (Port 8000)                │
│    /health  •  /api/v1/providers  •  /api/v1/rules          │
│    /api/v1/scans (POST)           •  /api/v1/scans/{id}     │
├─────────────────────────────────────────────────────────────┤
│                     Core Engine Pipeline                    │
│   [Upload Validator] ──> [Safe AST Parsers (HCL2/YAML)]     │
│          ──> [Canonical Normalizer & Secret Redactor]       │
│          ──> [Deterministic Rule Engine (25 Rules)]         │
│          ──> [Risk Scorer & Penalty Deductor]               │
├─────────────────────────────────────────────────────────────┤
│            SQLite WAL Database & Repositories               │
└─────────────────────────────────────────────────────────────┘
```

---

## Slide 5: The 25 Built-In Security Guardrails
### Comprehensive Multi-Cloud Coverage

| Cloud Provider | Rules | Monitored Services & Controls |
|---|---|---|
| **AWS** (11 Rules) | `IG-AWS-001` to `010`<br>`IG-IAM-001` | S3 Public Read/Write, S3 Block Public Access, Ingress SSH (22), Ingress RDP (3389), Permissive 0.0.0.0/0, RDS Public Access, RDS Storage Encryption, EBS Volume Encryption, S3 Bucket Logging, IAM Wildcard Admin Permissions |
| **Azure** (7 Rules) | `IG-AZ-001` to `007` | Storage Public Blob Access, NSG Ingress SSH (22), NSG Ingress RDP (3389), Storage Secure Transfer (HTTPS), Storage Infrastructure Encryption, NSG Permissive Any, Database Public Network Access |
| **GCP** (7 Rules) | `IG-GCP-001` to `007` | Cloud Storage Public IAM (`allUsers`), Firewall Ingress SSH (22), Firewall Ingress RDP (3389), Firewall Permissive 0.0.0.0/0, Uniform Bucket-Level Access, Public Access Prevention, Project IAM Broad Roles |

---

## Slide 6: Transparent Risk Scoring & Evaluation Semantics
### Honest Semantics: Never Assume Safety

- **Deterministic Penalty Model**:
  $$\text{Score} = \max\left(0, 100 - \sum \text{Severities}\right)$$
  - **Critical**: 25 points deduction
  - **High**: 15 points deduction
  - **Medium**: 7 points deduction
  - **Low**: 2 points deduction
- **Risk Classification Bands**:
  - `90 - 100`: **LOW**
  - `70 - 89`: **MODERATE**
  - `40 - 69`: **HIGH**
  - `0 - 39`: **CRITICAL**
- **Strict Evaluation Semantics**:
  - `PASS`: Configuration explicitly verifies compliant state.
  - `FAIL`: Direct misconfiguration detected with code evidence.
  - `NOT_EVALUATED`: Indeterminate or missing configuration.
  - `UNSUPPORTED`: Explicitly flagged outside scope; **never falsely marked PASS**.

---

## Slide 7: Security & Threat Modeling
### Defense-in-Depth for Safe Static Analysis

- **Memory-Safe Ingestion**:
  - Max single file upload: 5 MB
  - Max batch upload: 20 MB / 50 files
  - Path traversal stripping (`Path(filename).name`)
- **Safe Parsing**:
  - PyYAML `SafeLoader` with custom AWS intrinsic constructors (prevents object deserialization RCE).
  - Memory-only file streaming without arbitrary disk execution.
- **Zero Accidental Secret Leakage**:
  - Automatic in-flight secret redaction for credentials, passwords, tokens, AWS keys (`AKIA...`), and RSA private keys.
- **Hermetic Testing**:
  - Offline testing using synthetic fixtures—no cloud credentials or internet required.

---

## Slide 8: Verification, Test Metrics & Quality
### Enterprise Quality Engineering

| Metric | Result | Standard / Target |
|---|---|---|
| **Automated Tests** | **175 Passed** in ~2s | Comprehensive unit, integration, and security tests |
| **Backend Coverage** | **89%** | PRD requirement: $\ge 85\%$ |
| **Ruff Lint & Format** | **100% Clean** (0 errors) | Strict Python PEP 8 & modern typing rules |
| **CI / CD Pipeline** | **GitHub Actions** | Automated lint, test, and coverage gates |
| **Persistence** | **SQLite WAL Engine** | Verified across process reboots |
| **Export Formats** | **JSON & CSV** | Verified downloadable audit reports |

---

## Slide 9: Product Demonstration Highlights
### Experience the InfraGuard Workflow

1. **Service Health**: Instant real-time backend status checking (`/health`).
2. **Provider & Format Matching**: Dynamic selectboxes in Streamlit preventing invalid format submissions.
3. **Immediate Analysis**: Upload multi-cloud configurations and receive findings in under 1 second.
4. **Rich Visualizations**: Interactive Plotly charts for severity distributions and rule status metrics.
5. **Actionable Remediation**: Exact resource names, line evidence, and remediation steps.
6. **Audit Trail**: Full paginated scan history and one-click JSON/CSV exports.

---

## Slide 10: Future Roadmap (Enterprise Scale)
### Evolution Beyond the MVP

- **Enterprise IAM**: OIDC / SAML SSO integration and Role-Based Access Control (RBAC).
- **Multi-Tenancy**: Tenant-partitioned databases with organization-level scan isolation.
- **Enterprise Storage**: Transition to managed PostgreSQL with connection pooling.
- **Extended Formats**: Native Azure Bicep / ARM and GCP Deployment Manager / Terraform Plan JSON.
- **CI/CD Integrations**: Native GitHub Actions, GitLab CI, and Pre-commit hooks with customizable failure thresholds.
- **AI Remediation Assistant**: Optional LLM-assisted remediation code generation within an isolated sandbox.

---

## Slide 11: Conclusion & Acceptance Sign-off
### InfraGuard 1.0.0 MVP is Release Ready

- **All 15 PRD Acceptance Criteria Satisfied**
- **Robust Multi-Cloud Rules**: 25 Guardrails Implemented
- **High Performance & Coverage**: 175 Tests, 89% Code Coverage
- **Complete Documentation**: Architecture, Baseline, Threat Model, API Examples, Demo Script

*Ready for team deployment and production security auditing.*
