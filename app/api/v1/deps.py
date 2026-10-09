"""Shared FastAPI dependencies."""

from __future__ import annotations

from app.models.database import get_db

__all__ = ["get_db"]
