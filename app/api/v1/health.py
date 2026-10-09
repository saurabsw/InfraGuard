"""Health check endpoint.

GET /health — returns service status and version.
Not under /api/v1 prefix so load balancers and probes can reach it
without versioned paths.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.config import settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Returns current service status and version.",
)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
    )
