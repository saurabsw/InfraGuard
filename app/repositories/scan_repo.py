"""Repository for database operations on scans."""

from __future__ import annotations

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app.models.scan import ScanModel


class ScanRepository:
    """Repository handling persistence and queries for ScanModel."""

    def __init__(self, db: Session):
        self.db = db

    def create(self, scan: ScanModel) -> ScanModel:
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_by_id(self, scan_id: str) -> ScanModel | None:
        stmt = (
            select(ScanModel)
            .options(selectinload(ScanModel.findings))
            .where(ScanModel.id == scan_id)
        )
        return self.db.scalars(stmt).first()

    def list_paginated(
        self,
        page: int = 1,
        page_size: int = 20,
        provider: str | None = None,
    ) -> tuple[list[ScanModel], int]:
        base_query = select(ScanModel)
        count_query = select(func.count(ScanModel.id))

        if provider:
            base_query = base_query.where(ScanModel.provider == provider)
            count_query = count_query.where(ScanModel.provider == provider)

        total = self.db.scalar(count_query) or 0

        stmt = (
            base_query.options(selectinload(ScanModel.findings))
            .order_by(desc(ScanModel.created_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        items = list(self.db.scalars(stmt).all())
        return items, total

    def delete(self, scan_id: str) -> bool:
        scan = self.get_by_id(scan_id)
        if scan is None:
            return False
        self.db.delete(scan)
        self.db.commit()
        return True
