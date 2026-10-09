"""Report export service generating JSON and CSV exports."""

from __future__ import annotations

import csv
import io
import json

from app.models.scan import ScanModel
from app.schemas.report import ReportFormat


class ReportService:
    """Generates structured export reports for scans."""

    def generate_report(self, scan: ScanModel, fmt: ReportFormat) -> tuple[str, str]:
        """Generate report content and return (content_string, media_type)."""
        if fmt == ReportFormat.CSV:
            return self._generate_csv(scan), "text/csv"
        return self._generate_json(scan), "application/json"

    def _generate_json(self, scan: ScanModel) -> str:
        data = {
            "scan_id": scan.id,
            "created_at": scan.created_at.isoformat(),
            "provider": scan.provider,
            "format": scan.format,
            "status": scan.status,
            "scanner_version": scan.scanner_version,
            "policy_version": scan.policy_version,
            "summary": {
                "risk_score": scan.risk_score,
                "risk_band": scan.risk_band,
                "total_resources": scan.total_resources,
                "resources_evaluated": scan.resources_evaluated,
                "resources_unsupported": scan.resources_unsupported,
                "severity_counts": scan.severity_counts,
                "status_counts": scan.status_counts,
                "parser_error_count": scan.parser_error_count,
            },
            "findings": [
                {
                    "finding_id": f.id,
                    "rule_id": f.rule_id,
                    "provider": f.provider,
                    "severity": f.severity,
                    "status": f.status,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "source_file": f.source_file,
                    "source_location": f.source_location,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "reference_urls": f.reference_urls,
                }
                for f in scan.findings
            ],
            "diagnostics": scan.diagnostics_json or [],
        }
        return json.dumps(data, indent=2)

    def _generate_csv(self, scan: ScanModel) -> str:
        output = io.StringIO()
        fieldnames = [
            "finding_id",
            "scan_id",
            "rule_id",
            "provider",
            "severity",
            "status",
            "resource_id",
            "resource_type",
            "source_file",
            "source_location",
            "evidence",
            "remediation",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for f in scan.findings:
            writer.writerow(
                {
                    "finding_id": f.id,
                    "scan_id": scan.id,
                    "rule_id": f.rule_id,
                    "provider": f.provider,
                    "severity": f.severity,
                    "status": f.status,
                    "resource_id": f.resource_id,
                    "resource_type": f.resource_type,
                    "source_file": f.source_file,
                    "source_location": f.source_location or "",
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                }
            )

        return output.getvalue()
