# Indeterminate Terraform fixture — omitted or indeterminate security flags
# Should produce NOT_EVALUATED statuses

resource "aws_db_instance" "omitted_encryption" {
  allocated_storage = 20
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  # storage_encrypted omitted intentionally
}

resource "aws_ebs_volume" "omitted_ebs_encryption" {
  availability_zone = "us-east-1a"
  size              = 10
  # encrypted omitted intentionally
}

resource "azurerm_storage_account" "omitted_azure_props" {
  name                     = "indeterminate123"
  resource_group_name      = "rg-test"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # allow_nested_items_to_be_public and enable_https_traffic_only omitted
}
