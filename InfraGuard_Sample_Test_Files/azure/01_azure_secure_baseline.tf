# Synthetic secure Azure baseline. No deployment is required.
resource "azurerm_storage_account" "appdata" {
  name                     = "igsyntheticappdata001"
  resource_group_name      = "synthetic-rg"
  location                 = "Central India"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = false
  https_traffic_only_enabled     = true
  min_tls_version                = "TLS1_2"
}

resource "azurerm_network_security_group" "app" {
  name                = "synthetic-app-nsg"
  location            = "Central India"
  resource_group_name = "synthetic-rg"

  security_rule {
    name                       = "allow-https-approved-range"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.10.0.0/16"
    destination_address_prefix = "*"
  }
}
