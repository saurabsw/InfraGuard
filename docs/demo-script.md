# InfraGuard — Repeatable End-to-End Demonstration Script

> **Purpose:** Step-by-step verification guide for demonstrating InfraGuard's multi-cloud security auditing capabilities.  
> **Prerequisites:** Python 3.11+, installed virtual environment with `pip install -r requirements.txt`. No cloud credentials or cloud network connectivity required.

---

## 1. Environment Preparation & Service Startup

### Step 1.1: Start the FastAPI Backend
Open a terminal (Terminal 1) in the repository root and start the API server:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Expected output:**
```
INFO:     Started server process [...]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

### Step 1.2: Start the Streamlit Frontend
Open a second terminal (Terminal 2) and launch the dashboard:

```bash
streamlit run dashboard/app.py
```

**Expected output:**
```
You can now view your Streamlit app in your browser.
Local URL: http://localhost:8501
```

---

## 2. API Verification via Curl / HTTP

### Step 2.1: Verify Backend Health
```bash
curl -s http://127.0.0.1:8000/health | python -m json.tool
```
**Verify:** Response returns `"status": "healthy"`, `"database": "connected"`, `"rules_loaded": 25`.

### Step 2.2: Discover Providers & Formats
```bash
curl -s http://127.0.0.1:8000/api/v1/providers | python -m json.tool
```
**Verify:** Lists AWS (terraform, cloudformation), Azure (terraform), and GCP (terraform).

### Step 2.3: Query Security Rules Catalogue
```bash
curl -s "http://127.0.0.1:8000/api/v1/rules?severity=critical" | python -m json.tool
```
**Verify:** Returns all 12 critical guardrails across AWS, Azure, and GCP.

---

## 3. End-to-End Scans Using Synthetic Fixtures

### Step 3.1: Scan Insecure AWS Terraform Fixture
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans" \
  -F "provider=aws" \
  -F "format=terraform" \
  -F "files=@fixtures/aws/insecure.tf" | python -m json.tool
```
**Verify:**
- `status`: `"completed"`
- `risk_score`: `0` (or critical risk band)
- Detected findings:
  - `IG-AWS-001` (S3 Public Read)
  - `IG-AWS-003` (S3 Block Public Access Disabled)
  - `IG-AWS-004` (SSH Open to Internet on Port 22)
  - `IG-AWS-005` (RDP Open to Internet on Port 3389)
  - `IG-AWS-007` (RDS Publicly Accessible)
  - `IG-AWS-008` (RDS Storage Encryption Disabled)
  - `IG-AWS-009` (EBS Volume Unencrypted)
  - `IG-IAM-001` (Wildcard Admin IAM Permissions)

### Step 3.2: Scan Secure AWS Terraform Fixture
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans" \
  -F "provider=aws" \
  -F "format=terraform" \
  -F "files=@fixtures/aws/secure.tf" | python -m json.tool
```
**Verify:**
- `risk_score`: `100` (risk band: `LOW`)
- Total findings: `0`

### Step 3.3: Scan Insecure Azure Terraform Fixture
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans" \
  -F "provider=azure" \
  -F "format=terraform" \
  -F "files=@fixtures/azure/insecure.tf" | python -m json.tool
```
**Verify:**
- Detected findings:
  - `IG-AZ-001` (Public Blob Access Allowed)
  - `IG-AZ-002` (SSH Inbound Open on Port 22)
  - `IG-AZ-003` (RDP Inbound Open on Port 3389)
  - `IG-AZ-004` (Secure Transfer Disabled)
  - `IG-AZ-007` (Database Public Network Access Enabled)

### Step 3.4: Scan Insecure GCP Terraform Fixture
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans" \
  -F "provider=gcp" \
  -F "format=terraform" \
  -F "files=@fixtures/gcp/insecure.tf" | python -m json.tool
```
**Verify:**
- Detected findings:
  - `IG-GCP-001` (Cloud Storage Public IAM Access `allUsers`)
  - `IG-GCP-002` (Firewall SSH Open on Port 22)
  - `IG-GCP-003` (Firewall RDP Open on Port 3389)
  - `IG-GCP-005` (Uniform Bucket Level Access Disabled)
  - `IG-GCP-007` (Project IAM Broad Grants)

---

## 4. Streamlit Dashboard Demonstration

1. **Open Web Browser**: Navigate to `http://localhost:8501`.
2. **Observe Sidebar**:
   - Confirm backend connectivity indicator displays a green pill: **`Backend: Online (v1.0.0)`**.
3. **Execute a Scan in the UI**:
   - Click navigation item: **New Scan**.
   - Select Cloud Provider: **AWS**.
   - Notice the Configuration Format dropdown automatically updates to show **terraform** and **cloudformation**.
   - Upload sample file: Browse and choose `fixtures/aws/insecure.tf`.
   - Click **Start Security Audit**.
   - Observe progress spinner.
4. **Inspect Interactive Results**:
   - The view automatically transitions to the **Scan Results** page.
   - View the overall **Risk Score Gauge** and **CRITICAL** risk badge.
   - Interact with the **Plotly Severity Donut Chart** and hover over slices.
   - Expand the individual finding cards:
     - Notice the exact **Resource ID** (`aws_security_group.allow_ssh`).
     - Review the exact code **Evidence** line.
     - Review the actionable **Remediation Guidance**.
5. **Download Reports**:
   - Click **Download JSON Report** → Verifies structured machine-readable export.
   - Click **Download CSV Report** → Verifies tabular audit export.
6. **Browse History**:
   - Click navigation item: **Scan History**.
   - Observe the audit log containing all executed scans with timestamps, provider tags, and risk scores.
   - Click **Inspect Scan** on an earlier scan to reload its findings immediately.
7. **Rule Catalogue**:
   - Click navigation item: **Rule Catalogue**.
   - Filter by **Azure** or **Critical** to explore the built-in guardrails and rationales.

---

## 5. Input Validation & Error Handling Demonstration

### Step 5.1: Malformed HCL Syntax Test
```bash
curl -X POST "http://127.0.0.1:8000/api/v1/scans" \
  -F "provider=aws" \
  -F "format=terraform" \
  -F "files=@fixtures/aws/malformed.tf" | python -m json.tool
```
**Verify:** Scan completes with diagnostic notice recording syntax error: `parser_error_count > 0` and unparsed resources flagged without server crash.

### Step 5.2: File Size Limit Test
Submit a file larger than 5MB or invalid extension:
```bash
curl -i -X POST "http://127.0.0.1:8000/api/v1/scans" \
  -F "provider=aws" \
  -F "format=terraform" \
  -F "files=@README.md"
```
**Verify:** Server returns `400 Bad Request` with structured error details explaining unsupported extension `.md`.
