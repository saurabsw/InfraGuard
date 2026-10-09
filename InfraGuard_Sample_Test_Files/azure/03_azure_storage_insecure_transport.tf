# Intentionally insecure fixture: secure transfer is disabled.
resource "azurerm_storage_account" "legacy_transport" {
  name                     = "igsyntheticlegacy001"
  resource_group_name      = "synthetic-rg"
  location                 = "Central India"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = false
  https_traffic_only_enabled     = false
  min_tls_version                = "TLS1_0"
}
