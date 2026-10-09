# Intentionally insecure fixture: public blob access and SSH from any source.
resource "azurerm_storage_account" "publicdata" {
  name                     = "igsyntheticpublicdata001"
  resource_group_name      = "synthetic-rg"
  location                 = "Central India"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public = true
  https_traffic_only_enabled     = true
  min_tls_version                = "TLS1_2"
}

resource "azurerm_network_security_group" "open_ssh" {
  name                = "synthetic-open-ssh-nsg"
  location            = "Central India"
  resource_group_name = "synthetic-rg"

  security_rule {
    name                       = "allow-ssh-anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
