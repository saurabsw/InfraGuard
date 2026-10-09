"""Scan request and response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.constants import ConfigFormat, Provider, RiskBand, ScanStatus
from app.schemas.finding import FindingResponse


class DiagnosticResponse(BaseModel):
    """Parser diagnostic item."""

    file: str
    message: str
    severity: str
    line: int | None = None


class ScanSummaryResponse(BaseModel):
    """Aggregate metrics and posture summary for a scan."""

    risk_score: int | None
    risk_band: RiskBand | None
    total_resources: int
    resources_evaluated: int
    resources_unsupported: int
    severity_counts: dict[str, int]
    status_counts: dict[str, int]
    parser_error_count: int


class ScanResponse(BaseModel):
    """Full scan response including findings and diagnostics."""

    scan_id: str
    created_at: datetime
    provider: Provider
    format: ConfigFormat
    status: ScanStatus
    scanner_version: str
    policy_version: str
    summary: ScanSummaryResponse
    findings: list[FindingResponse] = Field(default_factory=list)
    diagnostics: list[DiagnosticResponse] = Field(default_factory=list)


class ScanHistoryItem(BaseModel):
    """Concise scan record for paginated history listings."""

    scan_id: str
    created_at: datetime
    provider: Provider
    format: ConfigFormat
    status: ScanStatus
    risk_score: int | None
    risk_band: RiskBand | None
    total_findings: int
    fail_count: int


class ScanHistoryResponse(BaseModel):
    """Paginated scan history response."""

    items: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int
    total_pages: int
