# InfraGuard — REST API Examples

All versioned API endpoints are served under `/api/v1`. The base URL for local development is `http://127.0.0.1:8000`.

---

## 1. Health Check

### Request
```bash
curl -X GET http://127.0.0.1:8000/health
```

### Response (`200 OK`)
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

---

## 2. Provider Discovery

### Request
```bash
curl -X GET http://127.0.0.1:8000/api/v1/providers
```

### Response (`200 OK`)
```json
{
  "providers": [
    {
      "id": "aws",
      "name": "Amazon Web Services",
      "supported_formats": [
        {
          "id": "terraform",
          "name": "Terraform HCL",
          "extensions": [".tf"]
        },
        {
          "id": "cloudformation",
          "name": "CloudFormation",
          "extensions": [".yaml", ".yml", ".json"]
        }
      ]
    },
    {
      "id": "azure",
      "name": "Microsoft Azure",
      "supported_formats": [
        {
          "id": "terraform",
          "name": "Terraform HCL",
          "extensions": [".tf"]
        }
      ]
    },
    {
      "id": "gcp",
      "name": "Google Cloud Platform",
      "supported_formats": [
        {
          "id": "terraform",
          "name": "Terraform HCL",
          "extensions": [".tf"]
        }
      ]
    }
  ]
}
```

---

## 3. Rule Catalogue

### Request (All Rules)
```bash
curl -X GET http://127.0.0.1:8000/api/v1/rules
```

### Request (Filter by Provider & Severity)
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/rules?provider=aws&severity=CRITICAL"
```

### Response (`200 OK`)
```json
{
  "total": 5,
  "policy_version": "1.0.0",
  "rules": [
    {
      "rule_id": "IG-AWS-001",
      "title": "S3 Public Read Access",
      "description": "Detect S3 bucket policies that explicitly permit public read access.",
      "provider": "aws",
      "severity": "CRITICAL",
      "resource_types": ["s3_bucket_policy"],
      "rationale": "Public read access allows anyone on the internet to read sensitive data.",
      "remediation": "Remove public principals from bucket policy statements granting read actions.",
      "references": [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
      ]
    }
  ]
}
```

---

## 4. Submit Security Scan

### Request (AWS Terraform)
```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -F "provider=aws" \
  -F "format=terraform" \
  -F "files=@fixtures/aws/terraform/insecure.tf"
```

### Response (`201 Created`)
```json
{
  "scan_id": "c01bf64c-b570-4929-9e07-3a1ad136d80f",
  "created_at": "2026-10-09T21:04:00.123456",
  "provider": "aws",
  "format": "terraform",
  "status": "completed",
  "scanner_version": "1.0.0",
  "policy_version": "1.0.0",
  "summary": {
    "risk_score": 0,
    "risk_band": "CRITICAL",
    "total_resources": 7,
    "resources_evaluated": 7,
    "resources_unsupported": 0,
    "severity_counts": {
      "CRITICAL": 6,
      "HIGH": 4,
      "MEDIUM": 1,
      "LOW": 0
    },
    "status_counts": {
      "PASS": 0,
      "FAIL": 11,
      "NOT_EVALUATED": 0,
      "UNSUPPORTED": 0
    },
    "parser_error_count": 0
  },
  "findings": [
    {
      "id": "18f5ec47-a8c6-4bfa-9f8e-d9a2ff169123",
      "rule_id": "IG-AWS-001",
      "provider": "aws",
      "severity": "CRITICAL",
      "status": "FAIL",
      "resource_id": "public_read_write",
      "resource_type": "s3_bucket_policy",
      "source_file": "insecure.tf",
      "source_location": null,
      "evidence": "Bucket policy grants public read permissions to '*'",
      "remediation": "Remove public principals from bucket policy statements granting read actions.",
      "reference_urls": []
    }
  ],
  "diagnostics": []
}
```

---

## 5. Paginated Scan History

### Request
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/scans?page=1&page_size=10"
```

### Response (`200 OK`)
```json
{
  "items": [
    {
      "scan_id": "c01bf64c-b570-4929-9e07-3a1ad136d80f",
      "created_at": "2026-10-09T21:04:00.123456",
      "provider": "aws",
      "format": "terraform",
      "status": "completed",
      "risk_score": 0,
      "risk_band": "CRITICAL",
      "total_findings": 11,
      "fail_count": 11
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 10,
  "total_pages": 1
}
```

---

## 6. Retrieve Scan by ID

### Request
```bash
curl -X GET http://127.0.0.1:8000/api/v1/scans/c01bf64c-b570-4929-9e07-3a1ad136d80f
```

---

## 7. Export Scan Report

### Request (JSON Export)
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/scans/c01bf64c-b570-4929-9e07-3a1ad136d80f/report?format=json" \
  -o scan_report.json
```

### Request (CSV Export)
```bash
curl -X GET "http://127.0.0.1:8000/api/v1/scans/c01bf64c-b570-4929-9e07-3a1ad136d80f/report?format=csv" \
  -o scan_report.csv
```

---

## 8. Error Responses

### Invalid Input (`422 Unprocessable Entity`)
```json
{
  "error": "VALIDATION_ERROR",
  "message": "Unsupported provider: 'oracle'",
  "details": [
    "Supported providers: aws, azure, gcp"
  ]
}
```

### Resource Not Found (`404 Not Found`)
```json
{
  "error": "NOT_FOUND",
  "message": "Scan not found: non-existent-id",
  "details": []
}
```
