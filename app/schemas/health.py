"""Health check response schema."""

from __future__ import annotations

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Response for GET /health."""

    status: str
    version: str
