"""Scans endpoints: submission, retrieval, history, and report export."""

from __future__ import annotations

import math

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Path,
    Query,
    Response,
    UploadFile,
)
from sqlalchemy.orm import Session

from app.api.v1.deps import get_db
from app.core.constants import ConfigFormat, EvaluationStatus, Provider, RiskBand, ScanStatus
from app.core.exceptions import ScanNotFoundError
from app.repositories.scan_repo import ScanRepository
from app.schemas.finding import FindingResponse
from app.schemas.report import ReportFormat
from app.schemas.scan import (
    DiagnosticResponse,
    ScanHistoryItem,
    ScanHistoryResponse,
    ScanResponse,
    ScanSummaryResponse,
)
from app.services.report_service import ReportService
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1", tags=["scans"])


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=201,
    summary="Submit infrastructure configuration for security audit",
    description="Uploads one or more IaC configuration files and runs a synchronous security scan.",
)
async def submit_scan(
    provider: str = Form(..., description="Cloud provider (aws, azure, gcp)"),
    format: str = Form(..., description="Configuration format (terraform, cloudformation)"),
    files: list[UploadFile] = File(..., description="One or more configuration files"),
    db: Session = Depends(get_db),
) -> ScanResponse:
    # Read files into memory
    file_tuples = []
    for f in files:
        content = await f.read()
        file_tuples.append((f.filename or "unknown", content))

    service = ScanService(db=db)
    return service.execute_scan(
        provider_str=provider,
        format_str=format,
        files=file_tuples,
    )


@router.get(
    "/scans",
    response_model=ScanHistoryResponse,
    summary="List scan history",
    description="Returns a paginated list of historical scans ordered by most recent first.",
)
async def list_scans(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    provider: Provider | None = Query(None, description="Filter by cloud provider"),
    db: Session = Depends(get_db),
) -> ScanHistoryResponse:
    repo = ScanRepository(db)
    items, total = repo.list_paginated(
        page=page,
        page_size=page_size,
        provider=provider.value if provider else None,
    )

    history_items = []
    for s in items:
        fail_count = sum(1 for f in s.findings if f.status == EvaluationStatus.FAIL.value)
        history_items.append(
            ScanHistoryItem(
                scan_id=s.id,
                created_at=s.created_at,
                provider=Provider(s.provider),
                format=ConfigFormat(s.format),
                status=ScanStatus(s.status),
                risk_score=s.risk_score,
                risk_band=RiskBand(s.risk_band) if s.risk_band else None,
                total_findings=len(s.findings),
                fail_count=fail_count,
            )
        )

    total_pages = math.ceil(total / page_size) if total > 0 else 1

    return ScanHistoryResponse(
        items=history_items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Retrieve scan details and findings",
    description="Returns complete details, findings, and diagnostics for a specific scan.",
)
async def get_scan(
    scan_id: str = Path(..., description="Unique scan ID"),
    db: Session = Depends(get_db),
) -> ScanResponse:
    repo = ScanRepository(db)
    scan = repo.get_by_id(scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)

    return ScanResponse(
        scan_id=scan.id,
        created_at=scan.created_at,
        provider=Provider(scan.provider),
        format=ConfigFormat(scan.format),
        status=ScanStatus(scan.status),
        scanner_version=scan.scanner_version,
        policy_version=scan.policy_version,
        summary=ScanSummaryResponse(
            risk_score=scan.risk_score,
            risk_band=RiskBand(scan.risk_band) if scan.risk_band else None,
            total_resources=scan.total_resources,
            resources_evaluated=scan.resources_evaluated,
            resources_unsupported=scan.resources_unsupported,
            severity_counts=scan.severity_counts,
            status_counts=scan.status_counts,
            parser_error_count=scan.parser_error_count,
        ),
        findings=[
            FindingResponse(
                id=f.id,
                rule_id=f.rule_id,
                provider=Provider(f.provider),
                severity=f.severity,
                status=EvaluationStatus(f.status),
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                source_file=f.source_file,
                source_location=f.source_location,
                evidence=f.evidence,
                remediation=f.remediation,
                reference_urls=f.reference_urls or [],
            )
            for f in scan.findings
        ],
        diagnostics=[
            DiagnosticResponse(
                file=d.get("file", ""),
                message=d.get("message", ""),
                severity=d.get("severity", "info"),
                line=d.get("line"),
            )
            for d in (scan.diagnostics_json or [])
        ],
    )


@router.get(
    "/scans/{scan_id}/report",
    summary="Export scan report in JSON or CSV format",
    description="Exports the complete scan report and findings in the requested format.",
)
async def export_report(
    scan_id: str = Path(..., description="Unique scan ID"),
    format: ReportFormat = Query(ReportFormat.JSON, description="Export format (json, csv)"),
    db: Session = Depends(get_db),
) -> Response:
    repo = ScanRepository(db)
    scan = repo.get_by_id(scan_id)
    if scan is None:
        raise ScanNotFoundError(scan_id)

    report_svc = ReportService()
    content, media_type = report_svc.generate_report(scan, format)

    filename = f"infraguard-scan-{scan_id}.{format.value}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
    }

    return Response(
        content=content,
        media_type=media_type,
        headers=headers,
    )
