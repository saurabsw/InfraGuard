"""Mappings for CloudFormation resources (AWS)."""

from __future__ import annotations

from app.core.constants import Provider

CLOUDFORMATION_RESOURCE_MAP: dict[str, tuple[Provider, str]] = {
    "AWS::S3::Bucket": (Provider.AWS, "s3_bucket"),
    "AWS::S3::BucketPolicy": (Provider.AWS, "s3_bucket_policy"),
    "AWS::EC2::SecurityGroup": (Provider.AWS, "security_group"),
    "AWS::RDS::DBInstance": (Provider.AWS, "rds_instance"),
    "AWS::EC2::Volume": (Provider.AWS, "ebs_volume"),
    "AWS::IAM::Policy": (Provider.AWS, "iam_policy"),
    "AWS::IAM::Role": (Provider.AWS, "iam_role_policy"),
}


def get_cloudformation_canonical_type(raw_type: str) -> tuple[Provider, str] | None:
    """Return provider and canonical resource type for CloudFormation resource."""
    return CLOUDFORMATION_RESOURCE_MAP.get(raw_type)
