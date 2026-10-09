"""V1 API router — aggregates all v1 sub-routers."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.providers import router as providers_router
from app.api.v1.rules import router as rules_router
from app.api.v1.scans import router as scans_router

router = APIRouter()

# Health is un-prefixed (accessible at /health)
router.include_router(health_router)

# All v1 routes are already prefixed in their own routers
router.include_router(providers_router)
router.include_router(rules_router)
router.include_router(scans_router)
