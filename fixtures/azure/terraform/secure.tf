# Secure Azure Terraform Infrastructure Fixture
# Complies with all Azure guardrails

resource "azurerm_storage_account" "secure_storage" {
  name                             = "securestorage123"
  resource_group_name              = "rg-sec"
  location                         = "eastus"
  account_tier                     = "Standard"
  account_replication_type         = "GRS"
  allow_nested_items_to_be_public  = false
  enable_https_traffic_only        = true
  infrastructure_encryption_enabled = true
}

resource "azurerm_network_security_group" "secure_nsg" {
  name                = "secure-nsg"
  location            = "eastus"
  resource_group_name = "rg-sec"

  security_rule {
    name                       = "allow-https-corp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.0.0.0/16"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-ssh-bastion"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.2.4/32"
    destination_address_prefix = "*"
  }
}

resource "azurerm_mssql_server" "secure_sql" {
  name                         = "securesqlserver123"
  resource_group_name          = "rg-sec"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "ComplexPassword1234!"
  public_network_access_enabled = false
}
