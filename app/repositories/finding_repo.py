"""Repository for database operations on findings."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.scan import FindingModel


class FindingRepository:
    """Repository handling persistence and queries for FindingModel."""

    def __init__(self, db: Session):
        self.db = db

    def create_batch(self, findings: list[FindingModel]) -> list[FindingModel]:
        self.db.add_all(findings)
        self.db.commit()
        return findings

    def list_by_scan_id(self, scan_id: str) -> list[FindingModel]:
        stmt = select(FindingModel).where(FindingModel.scan_id == scan_id)
        return list(self.db.scalars(stmt).all())
