"""Repositories package."""

from app.repositories.finding_repo import FindingRepository
from app.repositories.scan_repo import ScanRepository

__all__ = ["ScanRepository", "FindingRepository"]
