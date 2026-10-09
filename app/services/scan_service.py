"""Scan orchestration service.

Validates uploaded files, runs parsers and normalizer, executes the rule engine,
scores risk, and persists results via repositories (PRD §6, §9).
"""

from __future__ import annotations

from typing import BinaryIO
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.constants import (
    ConfigFormat,
    EvaluationStatus,
    Provider,
    ScanStatus,
    get_provider_info,
    is_valid_provider_format,
)
from app.core.exceptions import (
    FileCountExceededError,
    FileSizeExceededError,
    UnsupportedFormatError,
    ValidationError,
)
from app.engine.evaluator import RuleEvaluator
from app.models.scan import FindingModel, ScanModel
from app.normalization.normalizer import ResourceNormalizer
from app.parsers.base import ParseDiagnostic, ParsedResource
from app.parsers.registry import get_parser
from app.repositories.scan_repo import ScanRepository
from app.schemas.finding import FindingResponse
from app.schemas.scan import (
    DiagnosticResponse,
    ScanResponse,
    ScanSummaryResponse,
)
from app.scoring.scorer import RiskScorer


class ScanService:
    """Orchestrates end-to-end security scanning workflow."""

    def __init__(
        self,
        db: Session,
        normalizer: ResourceNormalizer | None = None,
        evaluator: RuleEvaluator | None = None,
        scorer: RiskScorer | None = None,
    ):
        self.db = db
        self.scan_repo = ScanRepository(db)
        self.normalizer = normalizer or ResourceNormalizer()
        self.evaluator = evaluator or RuleEvaluator()
        self.scorer = scorer or RiskScorer()

    def execute_scan(
        self,
        provider_str: str,
        format_str: str,
        files: list[tuple[str, BinaryIO | bytes]],  # [(filename, content)]
    ) -> ScanResponse:
        # 1. Validate Provider
        try:
            provider = Provider(provider_str.lower())
        except ValueError:
            raise ValidationError(
                f"Unsupported provider: '{provider_str}'",
                details=["Supported providers: aws, azure, gcp"],
            ) from None

        # 2. Validate Format
        try:
            config_format = ConfigFormat(format_str.lower())
        except ValueError:
            raise ValidationError(
                f"Unsupported format: '{format_str}'",
                details=["Supported formats: terraform, cloudformation"],
            ) from None

        # 3. Validate Provider + Format compatibility
        if not is_valid_provider_format(provider, config_format):
            raise UnsupportedFormatError(provider=provider.value, fmt=config_format.value)

        # 4. Validate Files Upload Limits
        if not files:
            raise ValidationError("At least one configuration file must be provided for scanning")

        if len(files) > settings.max_files_per_scan:
            raise FileCountExceededError(len(files), settings.max_files_per_scan)

        provider_info = get_provider_info(provider)
        allowed_extensions = provider_info.get_allowed_extensions()

        all_parsed_resources: list[ParsedResource] = []
        all_diagnostics: list[ParseDiagnostic] = []

        parser = get_parser(provider, config_format)

        for filename, content in files:
            # Check file extension
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in allowed_extensions:
                raise ValidationError(
                    f"File '{filename}' has invalid extension '{ext}'",
                    details=[
                        f"Allowed extensions for {provider.value}/{config_format.value}: {', '.join(sorted(allowed_extensions))}"
                    ],
                )

            # Check file size
            raw_bytes: bytes = content if isinstance(content, bytes) else content.read()
            if len(raw_bytes) > settings.max_file_size_bytes:
                raise FileSizeExceededError(filename, len(raw_bytes), settings.max_file_size_bytes)

            # Parse file
            parse_res = parser.parse(raw_bytes, filename, provider.value)
            all_parsed_resources.extend(parse_res.resources)
            all_diagnostics.extend(parse_res.diagnostics)

        # 5. Normalize Resources
        normalized_resources = self.normalizer.normalize(
            all_parsed_resources, provider, config_format
        )

        # 6. Evaluate Rules
        evaluation_results = self.evaluator.evaluate_resources(normalized_resources)

        # 7. Compute Scores
        score_summary = self.scorer.calculate_score(evaluation_results)

        # Count resource classifications
        total_res = len(normalized_resources)
        unsupported_res = sum(
            1 for r in normalized_resources if r.evaluation_status == EvaluationStatus.UNSUPPORTED
        )
        evaluated_res = total_res - unsupported_res

        parser_error_count = sum(1 for d in all_diagnostics if d.severity == "error")

        # 8. Persist to Database
        scan_id = str(uuid4())
        scan_model = ScanModel(
            id=scan_id,
            provider=provider.value,
            format=config_format.value,
            scanner_version=settings.scanner_version,
            policy_version=settings.policy_version,
            status=ScanStatus.COMPLETED.value,
            risk_score=score_summary.risk_score,
            risk_band=score_summary.risk_band.value,
            total_resources=total_res,
            resources_evaluated=evaluated_res,
            resources_unsupported=unsupported_res,
            severity_counts=score_summary.severity_counts,
            status_counts=score_summary.status_counts,
            parser_error_count=parser_error_count,
            diagnostics_json=[
                {
                    "file": d.file,
                    "message": d.message,
                    "severity": d.severity,
                    "line": d.line,
                }
                for d in all_diagnostics
            ],
        )

        finding_models: list[FindingModel] = []
        for r in evaluation_results:
            finding_models.append(
                FindingModel(
                    id=str(uuid4()),
                    scan_id=scan_id,
                    rule_id=r.rule_id,
                    provider=provider.value,
                    severity=r.severity.value,
                    status=r.status.value,
                    resource_id=r.resource_id,
                    resource_type=r.resource_type,
                    source_file=r.source_file,
                    source_location=r.source_location,
                    evidence=r.evidence,
                    remediation=r.remediation,
                    reference_urls=r.references,
                )
            )

        scan_model.findings = finding_models
        self.scan_repo.create(scan_model)

        # 9. Build API Response
        return ScanResponse(
            scan_id=scan_model.id,
            created_at=scan_model.created_at,
            provider=provider,
            format=config_format,
            status=ScanStatus(scan_model.status),
            scanner_version=scan_model.scanner_version,
            policy_version=scan_model.policy_version,
            summary=ScanSummaryResponse(
                risk_score=scan_model.risk_score,
                risk_band=score_summary.risk_band,
                total_resources=total_res,
                resources_evaluated=evaluated_res,
                resources_unsupported=unsupported_res,
                severity_counts=score_summary.severity_counts,
                status_counts=score_summary.status_counts,
                parser_error_count=parser_error_count,
            ),
            findings=[
                FindingResponse(
                    id=f.id,
                    rule_id=f.rule_id,
                    provider=provider,
                    severity=f.severity,
                    status=f.status,
                    resource_id=f.resource_id,
                    resource_type=f.resource_type,
                    source_file=f.source_file,
                    source_location=f.source_location,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    reference_urls=f.reference_urls,
                )
                for f in finding_models
            ],
            diagnostics=[
                DiagnosticResponse(
                    file=d.file,
                    message=d.message,
                    severity=d.severity,
                    line=d.line,
                )
                for d in all_diagnostics
            ],
        )
