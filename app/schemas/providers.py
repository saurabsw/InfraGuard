"""Provider discovery response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class FormatSchema(BaseModel):
    """A supported configuration format for a provider."""

    id: str
    name: str
    extensions: list[str]


class ProviderSchema(BaseModel):
    """A supported cloud provider with its formats."""

    id: str
    name: str
    supported_formats: list[FormatSchema]


class ProvidersResponse(BaseModel):
    """Response for GET /api/v1/providers."""

    providers: list[ProviderSchema]
