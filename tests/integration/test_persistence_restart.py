"""Integration test verifying persistence across application restarts."""

from __future__ import annotations

import tempfile
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models.database import Base
from app.repositories.scan_repo import ScanRepository
from app.services.scan_service import ScanService


class TestPersistenceAcrossRestarts:
    def test_scan_persists_across_engine_restarts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "persistent_test.db"
            db_url = f"sqlite:///{db_path}"

            # --- Session 1: Initialize DB and execute scan ---
            engine_1 = create_engine(db_url, connect_args={"check_same_thread": False})
            Base.metadata.create_all(bind=engine_1)

            with Session(bind=engine_1) as db_1:
                svc = ScanService(db=db_1)
                content = b'resource "aws_ebs_volume" "test_vol" { encrypted = true }'
                scan_res = svc.execute_scan(
                    provider_str="aws",
                    format_str="terraform",
                    files=[("vol.tf", content)],
                )
                saved_scan_id = scan_res.scan_id

            # Dispose engine 1 completely (simulates application termination)
            engine_1.dispose()

            # --- Session 2: Fresh engine on same DB file (simulates application restart) ---
            engine_2 = create_engine(db_url, connect_args={"check_same_thread": False})

            with Session(bind=engine_2) as db_2:
                repo_2 = ScanRepository(db_2)
                persisted_scan = repo_2.get_by_id(saved_scan_id)

                assert persisted_scan is not None
                assert persisted_scan.id == saved_scan_id
                assert persisted_scan.provider == "aws"
                assert persisted_scan.format == "terraform"
                assert persisted_scan.risk_score == 100
                assert len(persisted_scan.findings) == 1
                assert persisted_scan.findings[0].rule_id == "IG-AWS-009"
                assert persisted_scan.findings[0].status == "PASS"

            engine_2.dispose()
