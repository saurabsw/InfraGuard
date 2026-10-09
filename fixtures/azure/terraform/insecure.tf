# Insecure Azure Terraform Infrastructure Fixture
# Violates IG-AZ-001, IG-AZ-002, IG-AZ-003, IG-AZ-004, IG-AZ-005, IG-AZ-006, IG-AZ-007

resource "azurerm_storage_account" "insecure_storage" {
  name                             = "insecurestorage123"
  resource_group_name              = "rg-sec"
  location                         = "eastus"
  account_tier                     = "Standard"
  account_replication_type         = "LRS"
  allow_nested_items_to_be_public  = true
  enable_https_traffic_only        = false
  infrastructure_encryption_enabled = false
}

resource "azurerm_network_security_group" "insecure_nsg" {
  name                = "insecure-nsg"
  location            = "eastus"
  resource_group_name = "rg-sec"

  security_rule {
    name                       = "allow-ssh-internet"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-rdp-internet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "allow-all-inbound"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_mssql_server" "insecure_sql" {
  name                         = "insecuresqlserver123"
  resource_group_name          = "rg-sec"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "Password1234!"
  public_network_access_enabled = true
}
