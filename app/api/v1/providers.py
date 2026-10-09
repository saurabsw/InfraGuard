"""Provider discovery endpoint.

GET /api/v1/providers — returns supported providers and their formats.
The selected provider determines the applicable parser, resource
interpretation, and security rules (PRD §5).
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.constants import get_all_providers
from app.schemas.providers import (
    FormatSchema,
    ProviderSchema,
    ProvidersResponse,
)

router = APIRouter(prefix="/api/v1", tags=["providers"])


@router.get(
    "/providers",
    response_model=ProvidersResponse,
    summary="List supported cloud providers",
    description=(
        "Returns all supported cloud providers and their accepted "
        "configuration formats. Use these identifiers when submitting scans."
    ),
)
async def list_providers() -> ProvidersResponse:
    providers = []
    for info in get_all_providers():
        providers.append(
            ProviderSchema(
                id=info.provider_id.value,
                name=info.name,
                supported_formats=[
                    FormatSchema(
                        id=f.format_id.value,
                        name=f.name,
                        extensions=f.extensions,
                    )
                    for f in info.supported_formats
                ],
            )
        )
    return ProvidersResponse(providers=providers)
