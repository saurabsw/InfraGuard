"""Mappings for Terraform resources across AWS, Azure, and GCP."""

from __future__ import annotations

from app.core.constants import Provider

# Mapping of raw Terraform resource type -> (Provider, Canonical Resource Type)
TERRAFORM_RESOURCE_MAP: dict[str, tuple[Provider, str]] = {
    # AWS
    "aws_s3_bucket": (Provider.AWS, "s3_bucket"),
    "aws_s3_bucket_policy": (Provider.AWS, "s3_bucket_policy"),
    "aws_s3_bucket_public_access_block": (Provider.AWS, "s3_public_access_block"),
    "aws_s3_bucket_logging": (Provider.AWS, "s3_bucket_logging"),
    "aws_security_group": (Provider.AWS, "security_group"),
    "aws_security_group_rule": (Provider.AWS, "security_group_rule"),
    "aws_vpc_security_group_ingress_rule": (Provider.AWS, "security_group_rule"),
    "aws_db_instance": (Provider.AWS, "rds_instance"),
    "aws_ebs_volume": (Provider.AWS, "ebs_volume"),
    "aws_iam_policy": (Provider.AWS, "iam_policy"),
    "aws_iam_role_policy": (Provider.AWS, "iam_role_policy"),
    "aws_iam_policy_document": (Provider.AWS, "iam_policy_document"),
    "data.aws_iam_policy_document": (Provider.AWS, "iam_policy_document"),
    # Azure
    "azurerm_storage_account": (Provider.AZURE, "storage_account"),
    "azurerm_network_security_group": (Provider.AZURE, "network_security_group"),
    "azurerm_network_security_rule": (Provider.AZURE, "network_security_rule"),
    "azurerm_mssql_server": (Provider.AZURE, "sql_server"),
    "azurerm_postgresql_server": (Provider.AZURE, "postgresql_server"),
    "azurerm_mysql_server": (Provider.AZURE, "mysql_server"),
    # GCP
    "google_storage_bucket": (Provider.GCP, "storage_bucket"),
    "google_storage_bucket_iam_member": (Provider.GCP, "storage_iam_binding"),
    "google_storage_bucket_iam_binding": (Provider.GCP, "storage_iam_binding"),
    "google_compute_firewall": (Provider.GCP, "firewall_rule"),
    "google_project_iam_member": (Provider.GCP, "project_iam_binding"),
    "google_project_iam_binding": (Provider.GCP, "project_iam_binding"),
}


def get_terraform_canonical_type(raw_type: str) -> tuple[Provider, str] | None:
    """Return provider and canonical resource type if recognized."""
    return TERRAFORM_RESOURCE_MAP.get(raw_type)
