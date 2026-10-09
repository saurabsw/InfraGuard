# InfraGuard — Multi-Cloud Infrastructure Security Auditor

> **API-first** security scanning for AWS, Azure, and GCP infrastructure-as-code configurations.

InfraGuard performs static analysis of IaC templates (Terraform HCL, CloudFormation) to detect common security misconfigurations. It provides evidence-backed findings, deterministic risk scoring, and actionable remediation guidance — all through a documented REST API.

---

## Features

- **Multi-cloud**: AWS, Azure, and GCP support
- **Multi-format**: Terraform HCL and CloudFormation (AWS)
- **25 security rules**: S3, security groups, RDS, EBS, IAM (AWS), storage accounts, NSGs, databases (Azure), storage buckets, firewalls, IAM (GCP)
- **Deterministic scoring**: Severity-based penalty system with explainable risk bands
- **API-first**: Full REST API with OpenAPI documentation
- **Persistent history**: SQLite-backed scan history with JSON/CSV export
- **Interactive Dashboard**: Modern Streamlit frontend consuming the FastAPI REST API with live risk visualizations and history tracking

## Quick Start

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd infraguard

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env as needed (defaults work for local development)
```

### Run the API Server

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The API is now available at `http://127.0.0.1:8000`.

- **API Docs**: http://127.0.0.1:8000/docs
- **Health Check**: http://127.0.0.1:8000/health
- **Provider Discovery**: http://127.0.0.1:8000/api/v1/providers

### Run the Streamlit Dashboard

In a separate terminal (with backend running on `http://127.0.0.1:8000`):

```bash
streamlit run dashboard/app.py
```

The dashboard will open automatically in your browser (default: `http://localhost:8501`).

Features:
- **Live Health Status**: Real-time indicator of backend API connectivity in sidebar
- **Dynamic Provider/Format Filtering**: Cloud provider selection dynamically adapts supported IaC formats
- **File Upload & Client-Side Validation**: Multi-file upload with client-side extension and empty-file checking
- **Risk Score & Severity Visualizations**: Interactive Plotly doughnut chart of finding severities and status breakdown
- **Deep-Dive Findings**: Collapsible finding cards showing severity badges, failed resource IDs, line evidence, and remediation steps
- **Report Downloads**: One-click download of JSON audit reports and CSV tables directly from backend export endpoints
- **Historical Scan Viewer**: Browse paginated past audits with one-click reload into results viewer
- **Rule Catalogue Browser**: Filter and explore all 25 built-in security guardrails by provider and severity

### Run Tests

```bash
# Run all tests
pytest -v

# Run with coverage (backend)
pytest --cov=app --cov-report=term-missing -v

# Run only unit tests
pytest tests/unit/ -v

# Run only integration tests
pytest tests/integration/ -v
```

### Lint & Format

```bash
# Check linting
ruff check .

# Check formatting
ruff format --check .

# Auto-fix
ruff check --fix .
ruff format .
```

## Architecture

```
infraguard/
├── app/
│   ├── main.py              # FastAPI application factory
│   ├── core/                # Config, constants, exceptions
│   ├── schemas/             # Pydantic request/response models
│   ├── models/              # SQLAlchemy ORM models
│   ├── parsers/             # IaC format parsers (TF, CF)
│   ├── normalization/       # Resource normalization
│   ├── engine/              # Rule engine and evaluation
│   ├── rules/               # Security rule implementations
│   ├── scoring/             # Risk score calculation
│   ├── services/            # Scan orchestration
│   ├── repositories/        # Database access
│   └── api/v1/              # API route handlers
├── dashboard/               # Streamlit frontend (pure REST API client)
│   ├── api_client.py        # Typed HTTP client using httpx
│   └── app.py               # Multi-page interactive Streamlit UI
├── tests/                   # pytest test suite (175 tests, 89% backend coverage)
├── fixtures/                # Sample IaC configurations (AWS, Azure, GCP secure/insecure/malformed)
├── policies/                # Rule metadata and baseline v1.0.0
└── docs/                    # Documentation
    ├── architecture.md      # Comprehensive system architecture & data flow
    ├── security-baseline.md # Complete 25-rule security baseline reference with benchmarks
    ├── threat-model.md      # STRIDE & DREAD threat analysis and boundary guarantees
    ├── api-examples.md      # REST API request/response curl documentation
    ├── demo-script.md       # Repeatable end-to-end demonstration guide
    └── presentation.md      # 11-slide executive presentation deck
```

## API Endpoints

All endpoints are fully documented via interactive Swagger UI at `http://127.0.0.1:8000/docs` and detailed with curl examples in [`docs/api-examples.md`](docs/api-examples.md).

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health check |
| GET | `/api/v1/providers` | List supported providers and formats |
| GET | `/api/v1/rules` | List security rules (with provider/severity filters) |
| POST | `/api/v1/scans` | Submit configuration files for security scan |
| GET | `/api/v1/scans` | Paginated scan history |
| GET | `/api/v1/scans/{id}` | Full scan details, findings, and diagnostics |
| GET | `/api/v1/scans/{id}/report` | Export JSON/CSV scan report |

## Limitations

- **Static analysis only**: Does not connect to cloud accounts or inspect live resources
- **MVP rule set**: 25 rules covering common misconfigurations — not a full CIS/NIST audit
- **No authentication**: Local MVP is not safe for untrusted network exposure
- **SQLite**: Single-file database suitable for local use, not multi-replica production
- **Terraform variables**: Only default values are resolved; dynamic expressions → NOT_EVALUATED

## Technology Stack

| Component | Technology |
|-----------|------------|
| API | FastAPI + Pydantic |
| Database | SQLite (WAL mode) + SQLAlchemy 2.x |
| Parsers | python-hcl2, PyYAML |
| Testing | pytest + pytest-cov (175 tests, 89% coverage) |
| Linting | Ruff |
| CI | GitHub Actions |
| Frontend | Streamlit + Plotly (Decoupled REST API consumer) |

## License

Internal project — see repository for license terms.
