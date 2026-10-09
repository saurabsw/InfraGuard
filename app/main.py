"""FastAPI application factory.

Creates and configures the InfraGuard API application with:
- CORS middleware for frontend consumption
- Global exception handlers for structured error responses
- Database initialization on startup
- OpenAPI documentation at /docs (PRD §9)
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import router as v1_router
from app.core.config import settings
from app.core.exceptions import InfraGuardError, ValidationError
from app.models.database import init_db
from app.schemas.common import ErrorResponse

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — initialize DB on startup."""
    init_db()
    logger.info("InfraGuard %s started", settings.app_version)
    yield
    logger.info("InfraGuard shutting down")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Multi-Cloud Infrastructure Security Auditor — "
            "scans IaC configurations for security misconfigurations "
            "across AWS, Azure, and GCP."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS — allow Streamlit frontend and local dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Restrict in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------------------------------------------------------------
    # Global exception handlers — no stack traces to clients (PRD §13)
    # ---------------------------------------------------------------

    @app.exception_handler(ValidationError)
    async def validation_error_handler(_request: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error=exc.error_code,
                message=exc.message,
                details=exc.details,
            ).model_dump(),
        )

    @app.exception_handler(InfraGuardError)
    async def infraguard_error_handler(_request: Request, exc: InfraGuardError) -> JSONResponse:
        status = 404 if exc.error_code == "NOT_FOUND" else 500
        return JSONResponse(
            status_code=status,
            content=ErrorResponse(
                error=exc.error_code,
                message=exc.message,
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(_request: Request, _exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception")
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="INTERNAL_ERROR",
                message="An unexpected error occurred.",
            ).model_dump(),
        )

    # ---------------------------------------------------------------
    # Routes
    # ---------------------------------------------------------------
    app.include_router(v1_router)

    return app


# Application instance for uvicorn
app = create_app()
