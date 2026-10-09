\# InfraGuard — Multi-Cloud Infrastructure Security Auditor



\*\*Document type:\*\* Product Requirements Document (PRD)

\*\*Version:\*\* 1.0

\*\*Status:\*\* Initial implementation specification

\*\*Product owner:\*\* Saurabh

\*\*Implementation lead:\*\* AI coding agent

\*\*Primary objective:\*\* Deliver a demonstrable, independently usable, API-first infrastructure security auditing product.



\---



\## 1. Product Vision



InfraGuard is a Python-based application that scans infrastructure-as-code (IaC) configuration files for common security misconfigurations across AWS, Microsoft Azure, and Google Cloud Platform (GCP).



The product must identify risky configurations, provide evidence-backed findings, calculate an explainable risk score, recommend remediation, persist scan results, and expose all core functionality through a documented REST API.



A separate frontend will consume the backend APIs and provide an accessible, professional security dashboard.



The application is intended for security engineers, platform engineers, SRE teams, cloud architects, and DevSecOps practitioners.



\### Product principles



1\. API-first: all core scanning capabilities must work without the frontend.

2\. Secure by default: never execute uploaded configuration files or perform automatic infrastructure changes.

3\. Deterministic: identical inputs, policy versions, and scanner versions should produce consistent results.

4\. Explainable: every finding must have an identifiable rule and supporting evidence.

5\. Extensible: adding cloud providers, rules, parsers, authentication, or storage must not require rewriting the core engine.

6\. Honest evaluation: unsupported configurations and incomplete evaluations must never be represented as passing security checks.

7\. Test-driven quality: features must have automated tests and documented acceptance criteria.

8\. Time-conscious: prioritize a working, testable MVP over speculative features.



\## 2. Problem Statement



Infrastructure configurations can unintentionally expose cloud resources, permit overly broad network access, disable encryption, or grant excessive permissions.



Manual reviews are inconsistent and difficult to scale. InfraGuard provides a repeatable scanning workflow that identifies selected configuration risks before deployment.



The MVP performs static analysis only. It does not connect to cloud accounts, inspect live cloud resources, certify regulatory compliance, or deploy infrastructure.



\## 3. Target Users and Use Cases



\### Primary users



\* Cloud/platform engineers validating infrastructure changes.

\* Security engineers reviewing IaC configurations.

\* SRE and DevOps teams integrating security checks into delivery workflows.

\* Engineering managers reviewing aggregated risk and remediation priorities.



\### Core use cases



1\. Select AWS, Azure, or GCP.

2\. Select a supported configuration format.

3\. Upload one or more supported configuration files or a ZIP archive.

4\. Run a security scan against the applicable baseline.

5\. Review findings by severity, rule, resource, and source location.

6\. Understand why a finding was raised and how to remediate it.

7\. Review a transparent overall risk score.

8\. Retrieve the same results using REST API calls.

9\. Review previous scans and export reports.

10\. Repeat a scan after remediation and compare outcomes.



\## 4. Scope and Delivery Priorities



\### P0 — Mandatory MVP



\* Python FastAPI backend.

\* AWS, Azure, and GCP cloud selection.

\* Terraform HCL scanning for the supported resources of all three providers.

\* Provider-specific, versioned security rules.

\* CloudFormation support for AWS.

\* Azure ARM JSON template support.

\* GCP native template support only if its parser and test coverage fit the MVP time budget; otherwise document it as a planned extension.

\* Common normalized resource model.

\* Deterministic rule engine and severity-based risk score.

\* SQLite persistence.

\* Scan history and JSON/CSV report exports.

\* Streamlit frontend consuming REST APIs.

\* Automated unit and integration tests.

\* Ruff linting and GitHub Actions CI.

\* Sample secure and insecure configuration fixtures.

\* README, architecture document, security baseline, threat model, and prompts.md.



\### P1 — Implement if time permits



\* ZIP upload with archive safety controls.

\* Source line references for findings.

\* Scan-to-scan comparison.

\* Policy filtering by severity and rule.

\* Docker Compose setup.

\* More native configuration formats.

\* Additional cloud-specific rules.

\* A report with a summary suitable for sharing with engineering leadership.



\### P2 — Future roadmap



\* Authentication through an enterprise identity provider using OIDC.

\* Role-based access control and tenant isolation.

\* PostgreSQL and database migrations.

\* LLM-assisted explanations and remediation proposals.

\* Human-reviewed, downloadable remediation patches.

\* Kubernetes deployment with Helm.

\* CI/CD integration and pull-request comments.

\* Policy exceptions, approvals, and expiry.

\* Centralized logs, metrics, tracing, and operational dashboards.

\* Additional IaC formats and cloud providers.



P1 and P2 must not delay a working P0 release.



\## 5. Supported Cloud Platforms and Input Formats



\### Cloud selector



The frontend must present a dropdown with:



\* AWS

\* Microsoft Azure

\* Google Cloud Platform (GCP)



The API must accept the same canonical provider identifiers: `aws`, `azure`, and `gcp`.



The selected provider determines the applicable parser, resource interpretation, and security rules.



The provider must be explicitly selected and validated. Do not silently infer a different cloud provider from uploaded content when that would conflict with the user's selection.



\### Format and provider compatibility



| Provider | MVP format                              | Planned or conditional format                         |

| -------- | --------------------------------------- | ----------------------------------------------------- |

| AWS      | Terraform HCL; CloudFormation YAML/JSON | Additional AWS deployment formats                     |

| Azure    | Terraform HCL                           | Azure ARM JSON                                        |

| GCP      | Terraform HCL                           | Google Cloud Deployment Manager YAML/JSON if feasible |



Native formats must be implemented through separate parser adapters. Do not claim a format is supported until its parsing and security behavior are covered by tests.



Google Cloud Deployment Manager is a legacy format; prioritize Terraform for current GCP support and document any Deployment Manager support as compatibility for existing templates.



\### Upload validation



\* Support explicitly configured extensions and file formats.

\* Apply configurable file-size, file-count, and archive-size limits.

\* Validate file contents rather than trusting filenames or MIME types.

\* Reject path traversal, unsafe archive entries, and unsupported files.

\* Reject malformed configuration with clear error responses.

\* Never execute uploaded files, Terraform commands, shell commands, or deployment plans.

\* Do not require or accept cloud credentials in the MVP.

\* Do not log raw configuration content or potential secrets.

\* Return unsupported or indeterminate evaluations explicitly.



\## 6. Architecture and Design Requirements



Use a modular monolith, not microservices.



\### Technology stack



\* Python 3.12.

\* FastAPI and Pydantic.

\* SQLAlchemy 2.x.

\* SQLite for local MVP persistence.

\* pytest and pytest-cov.

\* Ruff for linting and formatting.

\* Streamlit and Plotly for the frontend.

\* Terraform HCL parser such as python-hcl2.

\* Safe YAML parsing and JSON parsing for supported native templates.

\* GitHub Actions for CI.

\* Docker and Docker Compose where feasible.



Pin compatible dependency versions and maintain a reproducible dependency manifest. Use environment variables for configuration. Never commit secrets.



\### Required module boundaries



\* `api`: routes, request/response schemas, API error handling.

\* `core`: configuration, logging, exceptions, and shared constants.

\* `parsers`: provider-aware format adapters.

\* `normalization`: common resource model.

\* `engine`: policy registry, rule execution, and evaluation results.

\* `scoring`: risk scoring and score bands.

\* `services`: scan orchestration and reporting.

\* `repositories`: database access and persistence.

\* `models`: SQLAlchemy database models.

\* `dashboard`: separate Streamlit entry point.

\* `tests`: unit, integration, security, and regression tests.

\* `policies`: versioned baseline and rule metadata.

\* `fixtures`: synthetic test and demonstration configurations.



The policy engine must not depend on FastAPI, Streamlit, or SQLAlchemy. The frontend must not access database tables directly.



\### Parser adapter contract



Each parser must implement a documented interface that accepts validated input and returns:



\* Parsed resources.

\* Provider and resource type.

\* Stable resource identifier where available.

\* Extracted properties required by supported rules.

\* Source file and source location where available.

\* Parse diagnostics.

\* Unsupported or indeterminate constructs.



Parsing failures must be represented as structured errors. A parser must never silently discard an entire file and report a clean scan.



\### Normalized resource model



Each normalized resource should contain:



\* `provider`

\* `resource\_type`

\* `resource\_id`

\* `source\_file`

\* `source\_location`

\* `properties`

\* `evaluation\_status`



Only extract properties necessary for analysis. Avoid retaining raw uploaded content in the database unless explicitly required.



\## 7. Security Baseline and Rule Engine



Maintain a versioned, documented baseline. Use established references such as OWASP IaC security guidance, AWS Foundational Security Best Practices, and relevant official Azure and Google Cloud security documentation.



The initial baseline is a limited, project-defined set of controls inspired by these references. It must not claim full CIS, NIST, or provider certification.



Each rule must include:



\* Unique, stable rule ID.

\* Provider and supported resource types.

\* Rule name and description.

\* Severity.

\* Security rationale.

\* Preconditions and applicability.

\* Deterministic detection logic.

\* Required evidence.

\* Remediation guidance.

\* Secure example where appropriate.

\* Reference URLs.

\* Positive, negative, and edge-case unit tests.



\### Initial AWS rules



\* IG-AWS-001: Detect S3 bucket policies that explicitly permit public read access.

\* IG-AWS-002: Detect S3 bucket policies that permit public write access.

\* IG-AWS-003: Detect missing or explicitly disabled S3 Block Public Access settings where applicable.

\* IG-AWS-004: Detect internet-wide SSH ingress on port 22.

\* IG-AWS-005: Detect internet-wide RDP ingress on port 3389.

\* IG-AWS-006: Detect overly permissive inbound network rules, including unrestricted all-protocol ingress.

\* IG-AWS-007: Detect RDS resources configured for public accessibility.

\* IG-AWS-008: Detect disabled RDS storage encryption where the configuration explicitly establishes that state.

\* IG-AWS-009: Detect unencrypted EBS volumes where the configuration explicitly establishes that state.

\* IG-IAM-001: Detect overly broad IAM permissions, such as wildcard actions and resources in sensitive policies.

\* IG-AWS-010: Detect missing explicit S3 server access logging configuration where applicable.



\### Initial Azure rules



\* IG-AZ-001: Detect storage accounts that allow public blob access when the configuration establishes this state.

\* IG-AZ-002: Detect network security rules that expose SSH to the internet.

\* IG-AZ-003: Detect network security rules that expose RDP to the internet.

\* IG-AZ-004: Detect storage accounts without explicitly enabled secure transfer.

\* IG-AZ-005: Detect storage accounts without explicitly enabled infrastructure encryption or supported encryption protections, where applicable.

\* IG-AZ-006: Detect overly permissive network security rules.

\* IG-AZ-007: Detect databases configured for public network access when the resource model supports this property.



\### Initial GCP rules



\* IG-GCP-001: Detect Cloud Storage IAM bindings that grant public access to `allUsers` or `allAuthenticatedUsers`.

\* IG-GCP-002: Detect firewall rules that expose SSH to the internet.

\* IG-GCP-003: Detect firewall rules that expose RDP to the internet.

\* IG-GCP-004: Detect overly broad firewall ingress rules.

\* IG-GCP-005: Detect storage buckets without explicitly enabled uniform bucket-level access, where applicable.

\* IG-GCP-006: Detect storage buckets without explicitly configured public access prevention where applicable.

\* IG-GCP-007: Detect overly broad IAM grants when represented in supported resources.



These are initial candidate controls, not a guarantee that every property can be evaluated in every IaC format. Implement only rules with valid resource semantics and tested detection logic. Clearly mark unimplemented rules as planned rather than returning false PASS results.



\### Evaluation statuses



Use explicit statuses:



\* `PASS`: sufficient configuration evidence establishes that the supported check passes.

\* `FAIL`: the supported rule detects a violation.

\* `NOT\_EVALUATED`: insufficient or indeterminate information prevents a conclusion.

\* `UNSUPPORTED`: the resource or configuration construct is outside the supported scope.



Parser errors must also be exposed separately from rule evaluation results.



A resource that does not apply to a rule should not automatically be counted as a passing resource.



\## 8. Severity and Risk Scoring



Use severity levels:



\* Critical: 25 penalty points.

\* High: 15 penalty points.

\* Medium: 7 penalty points.

\* Low: 3 penalty points.



The initial risk score is:



`max(0, 100 - sum of finding penalties)`



Score bands:



\* 90–100: Low.

\* 70–89: Moderate.

\* 40–69: High.

\* 0–39: Critical.



These are project-defined heuristics, not an industry-standard risk formula. Document this limitation and show the underlying severity counts alongside the score.



Do not imply that a high score certifies compliance or that an incomplete scan is secure. Show scan completeness, unsupported resources, parser errors, and unevaluated checks separately.



Use deterministic scoring. Do not allow an LLM to change findings, severities, or the score.



\## 9. REST API Requirements



Use the `/api/v1` prefix for versioned application APIs.



Required endpoints:



\* `GET /health`: service health.

\* `GET /api/v1/providers`: supported providers and their formats.

\* `GET /api/v1/rules`: applicable rules and metadata, with optional provider and severity filters.

\* `POST /api/v1/scans`: submit a scan.

\* `GET /api/v1/scans`: paginated scan history.

\* `GET /api/v1/scans/{scan\_id}`: retrieve scan summary and findings.

\* `GET /api/v1/scans/{scan\_id}/report`: export JSON or CSV.

\* `GET /docs`: interactive OpenAPI documentation.



The scan request should identify the provider and format and contain one or more validated files. Use multipart upload for file submissions.



For the local MVP, synchronous scanning is acceptable. The API must return a clear status, scan ID, summary, findings, and diagnostics. Use an explicit response schema rather than returning arbitrary internal objects.



Use appropriate HTTP status codes, stable error structures, input validation, and documented request examples.



Avoid unbounded uploads, unbounded in-memory processing, and excessively detailed internal error messages.



\### Future API compatibility



\* Version endpoints and document contract changes.

\* Keep response schemas independent of internal database models.

\* Introduce authentication and authorization through dependencies/middleware.

\* Keep provider adapters and rule engine independently testable.

\* Support future background scan execution without changing the meaning of the scan result contract.



\## 10. Database and Persistence



Use SQLite with SQLAlchemy.



Minimum entities:



\### Scan



\* ID.

\* Created timestamp.

\* Provider.

\* Configuration format.

\* Scanner version.

\* Policy baseline version.

\* Status.

\* Risk score.

\* Severity counts.

\* Resource counts.

\* Evaluation completeness summary.

\* Parser diagnostics summary.



\### Finding



\* ID.

\* Scan ID.

\* Rule ID.

\* Provider.

\* Severity.

\* Evaluation status.

\* Resource identifier.

\* Source file and location.

\* Evidence.

\* Remediation guidance.

\* Reference metadata.



\### Policy metadata



Track policy version and enabled rule identifiers so historical scans can be interpreted against the rules that produced them.



Use repository/service boundaries. Avoid direct database access from route handlers and dashboard components.



Do not store cloud credentials or raw secrets. Establish retention and deletion behavior. SQLite is an MVP choice; use migrations and a repository abstraction when moving toward PostgreSQL.



\## 11. Frontend Requirements — Phase 2



The frontend must call the FastAPI service over HTTP and must not import or call internal backend modules.



\### Pages and components



1\. \*\*Overview dashboard\*\*



&#x20;  \* Recent scan count.

&#x20;  \* Latest risk score.

&#x20;  \* Severity distribution.

&#x20;  \* Recent scan history.

&#x20;  \* Scan completeness indicators.



2\. \*\*New scan\*\*



&#x20;  \* Provider dropdown: AWS, Azure, GCP.

&#x20;  \* Format dropdown filtered by provider.

&#x20;  \* File upload.

&#x20;  \* Validation messages.

&#x20;  \* Scan progress or result state.



3\. \*\*Scan results\*\*



&#x20;  \* Overall score and severity counts.

&#x20;  \* Findings grouped by severity and rule.

&#x20;  \* Resource and source location.

&#x20;  \* Evidence, rationale, remediation, and reference.

&#x20;  \* Parser errors and unsupported resources.



4\. \*\*Scan history\*\*



&#x20;  \* Search and pagination.

&#x20;  \* Provider and date filters.

&#x20;  \* Open previous results.

&#x20;  \* Compare scans if time permits.



5\. \*\*Rule catalogue\*\*



&#x20;  \* Rule ID, severity, provider, description, and remediation.

&#x20;  \* Applicable baseline and reference links.



\### UX requirements



\* Professional, uncluttered interface.

\* Clear distinction between PASS, FAIL, NOT\_EVALUATED, and UNSUPPORTED.

\* Accessible colors and readable severity labels.

\* Loading, empty, error, and success states.

\* Confirmation before destructive UI actions.

\* Configurable backend base URL.

\* No direct database calls.

\* No credentials embedded in frontend source.



\## 12. Testing and Quality Gates



Use pytest for all automated testing.



\### Unit tests



\* Each implemented rule has positive and negative tests.

\* Edge cases and missing properties are tested.

\* Parser normalization is tested.

\* Scoring and severity bands are tested.

\* Unsupported and indeterminate results are tested.

\* Policy registry consistency is tested.



\### Integration tests



\* API accepts a valid fixture and returns expected findings.

\* API rejects invalid provider/format combinations.

\* Scan results persist and can be retrieved.

\* History pagination works.

\* JSON/CSV export matches stored results.

\* Malformed inputs produce controlled errors.

\* The frontend can consume API responses from the documented contract.



\### Security tests



\* Oversized uploads are rejected.

\* ZIP traversal and unsafe archive entries are rejected.

\* Malformed YAML/JSON/HCL are handled safely.

\* Uploaded configuration is never executed.

\* Secrets are not included in application logs.

\* Error responses do not expose stack traces to clients.

\* Unsupported expressions do not generate false compliance results.



\### Quality gates



\* All mandatory automated tests pass.

\* Core rule engine and scoring logic target at least 85% line coverage.

\* Ruff checks pass.

\* CI runs linting and tests.

\* No secrets or cloud credentials are committed.

\* All implemented rules have documentation and regression fixtures.



Report coverage honestly. Do not weaken or delete tests to achieve a target.



\## 13. Security and Threat Model



Consider at minimum:



\* Malicious uploaded configuration.

\* Archive path traversal and decompression bombs.

\* Oversized or deeply nested files.

\* YAML parser abuse.

\* Accidental secret exposure through logs or reports.

\* Denial of service through repeated or expensive scans.

\* Cross-tenant data leakage in the future authenticated product.

\* Unauthorized report access in a future multi-user deployment.

\* Dependency vulnerabilities.



For the unauthenticated local MVP, explicitly document that it is not safe to expose to an untrusted public network. Apply upload limits, safe parsers, error sanitization, and resource limits.



Do not execute Terraform, shell commands, or user-supplied code. Do not automatically apply remediation.



\## 14. Future Architecture Requirements



Do not implement the entire future roadmap in the MVP. Keep clean extension points.



\### Authentication and authorization



Future design:



\* OIDC/OAuth2 enterprise login.

\* Role-based authorization.

\* Tenant-aware database records and queries.

\* Ownership checks for scans and reports.

\* Secrets managed through deployment configuration or a secret manager.

\* Authentication and authorization tests.



Do not claim tenant isolation until it is actually implemented and tested.



\### LLM-assisted explanations



Future design:



\* Optional explanation service behind a defined interface.

\* LLM receives sanitized findings and relevant policy metadata.

\* LLM output is advisory only.

\* Deterministic engine remains the source of truth.

\* Never send full uploaded files or secrets to a model by default.

\* Provide a fallback if the LLM is unavailable.

\* Validate model output against a schema.

\* Test hallucination, prompt injection, and unsafe remediation scenarios.

\* Never execute generated remediation commands automatically.



\### Kubernetes and production deployment



Future design:



\* Containerized API and frontend.

\* Helm chart or Kubernetes manifests.

\* Configurable resource requests and limits.

\* Readiness and liveness probes.

\* Non-root container execution.

\* Read-only root filesystem where practical.

\* Network policies and least-privilege service accounts.

\* Centralized structured logs, metrics, and traces.

\* External persistent database for multi-replica production deployments.

\* Secret management and deployment-specific configuration.

\* CI build, vulnerability scanning, and deployment gates.



Do not use a local SQLite file as shared production storage across multiple replicas.



\### CI/CD and enterprise integrations



Future design:



\* Command-line client or CI action.

\* Pull-request scanning and annotations.

\* Configurable severity thresholds.

\* Policy exception workflows with owners and expiry.

\* Signed or auditable reports.

\* Integration with ticketing systems and security reporting tools.



\## 15. Documentation and Submission Deliverables



The repository must contain:



\* `README.md`: setup, architecture summary, features, usage, limitations, and troubleshooting.

\* `PRD.md`: this specification, updated when scope changes.

\* `prompts.md`: chronological audit log of every prompt sent to the coding agent.

\* `docs/architecture.md`: components, boundaries, and data flow.

\* `docs/security-baseline.md`: implemented rules, references, applicability, and limitations.

\* `docs/threat-model.md`: threats, mitigations, and known risks.

\* `docs/api-examples.md`: sample API calls and responses.

\* `docs/demo-script.md`: repeatable demonstration steps.

\* AI-generated presentation deck or Markdown solution.

\* Synthetic sample configurations and expected findings.

\* Automated test suite and CI workflow.



Never fabricate test results, coverage, cloud compliance, or Tagle.ai output.



\## 16. Acceptance Criteria



The MVP is accepted when:



1\. The backend starts from documented commands.

2\. Provider discovery returns AWS, Azure, and GCP.

3\. Supported Terraform fixtures can be scanned for each provider.

4\. Supported native templates are scanned only where implementation and tests confirm support.

5\. Implemented rules produce expected findings on insecure fixtures.

6\. Secure fixtures pass applicable, fully evaluated checks.

7\. Unknown or unsupported constructs are visible and not falsely marked secure.

8\. Risk scores are reproducible and explainable.

9\. Scan results persist and are retrievable via API.

10\. JSON/CSV reports can be exported.

11\. The Streamlit frontend uses only the published backend APIs.

12\. Unit and integration tests pass, with coverage reported.

13\. Ruff and CI checks pass.

14\. The repository has complete setup and security documentation.

15\. The complete demonstration works using synthetic files and no cloud credentials.



\## 17. Implementation Strategy



Build in two principal phases.



\*\*Phase 1 — Backend\*\*



\* Approve architecture and acceptance criteria.

\* Implement project skeleton, schemas, and provider registry.

\* Implement parsers and normalized resource model.

\* Implement and test the policy engine.

\* Add scoring and report generation.

\* Add database and repositories.

\* Implement FastAPI endpoints.

\* Complete unit, integration, and security tests.

\* Validate through API calls without using the frontend.



\*\*Phase 2 — Frontend\*\*



\* Build the provider and format selectors.

\* Implement upload and scan submission.

\* Render scores, findings, evidence, and remediation.

\* Add scan history and report downloads.

\* Validate API error handling and empty states.

\* Demonstrate that frontend actions correspond to actual backend API calls.



Keep both phases within the challenge's time limit. If necessary, reduce the number of implemented rules or native formats, but do not compromise testability or misrepresent unsupported features.



\## 18. Definition of Done



A feature is not complete merely because code has been generated.



It is complete only when the implementation exists, automated tests have been executed, expected behavior has been verified, documentation has been updated, and limitations have been recorded.



The coding agent must report actual test output, coverage, changed files, remaining issues, and elapsed time after each implementation milestone.



The final deliverable must be reproducible from a clean checkout using the README instructions.



