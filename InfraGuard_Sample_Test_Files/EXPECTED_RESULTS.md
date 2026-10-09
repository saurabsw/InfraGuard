# Expected Results / Validation Matrix

Use this as a manual QA checklist. The expected rule names are descriptive; map them to the rule IDs actually exposed by your InfraGuard rule catalog.

| Fixture | Intended result if corresponding rules are implemented | What to verify |
|---|---|---|
| `aws/01_aws_secure_baseline.tf` | No findings for the controls represented in the file | Secure settings are recognized; no false positive for those controls |
| `aws/02_aws_public_s3_and_open_ssh.tf` | FAIL: public S3 access; FAIL: SSH open to the internet | Both findings identify the relevant resource and severity |
| `aws/03_aws_rds_public_unencrypted.tf` | FAIL: public RDS; FAIL: storage encryption disabled | Both independent violations appear |
| `azure/01_azure_secure_baseline.tf` | No findings for the controls represented in the file | Secure settings are recognized |
| `azure/02_azure_public_storage_and_open_nsg.tf` | FAIL: public blob access; FAIL: unrestricted SSH ingress | Both findings appear |
| `azure/03_azure_storage_insecure_transport.tf` | FAIL: secure transfer disabled | Correct resource and remediation guidance |
| `gcp/01_gcp_secure_baseline.tf` | No findings for the controls represented in the file | Secure settings are recognized |
| `gcp/02_gcp_public_bucket_and_open_ssh.tf` | FAIL: public bucket IAM; FAIL: SSH open to the internet | Both findings appear |
| `gcp/03_gcp_public_firewall_ingress.tf` | FAIL: broad ingress | Firewall rule and port/range are reported |
| `edge/01_minimal_valid.tf` | Valid parse; controls not represented should be NOT_EVALUATED where applicable | No parser crash; no blanket PASS |
| `edge/02_malformed_hcl.tf` | Parse error with a sanitized, actionable message | Scan fails safely; no stack trace or secret leakage |
| `edge/03_unknown_resource.tf` | UNSUPPORTED or NOT_EVALUATED for the unknown resource | Unknown resource is not silently treated as PASS |
| `edge/04_sensitive_placeholder.tf` | No real secret exists; placeholder should be redacted if echoed | Uploaded content is not copied into logs or errors unnecessarily |

## Suggested smoke-test acceptance criteria
- Each fixture can be uploaded independently.
- Valid fixtures create a scan record and a report.
- Malformed HCL produces a controlled error, not a server crash.
- A single scan can report multiple findings.
- Findings include rule ID/name, severity, resource address, evidence that is safe to display, and remediation.
- Scan history and report endpoints remain consistent after refresh.
- Unsupported resources are not reported as passing.
- No Terraform plan/apply/init or other uploaded code is executed.
