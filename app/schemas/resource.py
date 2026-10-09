"""Normalized resource schema.

Provider-agnostic representation of infrastructure resources used
for uniform security rule evaluation (PRD §6).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import EvaluationStatus, Provider


class NormalizedResource(BaseModel):
    """Normalized, provider-agnostic infrastructure resource."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    provider: Provider
    resource_type: str  # Canonical resource type (e.g. s3_bucket, security_group)
    resource_id: str  # Logical name or identifier
    source_file: str
    source_location: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    raw_type: str = ""  # Original type from IaC (e.g. aws_s3_bucket or AWS::S3::Bucket)
    evaluation_status: EvaluationStatus = EvaluationStatus.NOT_EVALUATED
