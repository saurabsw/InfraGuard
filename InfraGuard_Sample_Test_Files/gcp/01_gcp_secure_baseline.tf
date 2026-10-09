# Synthetic secure GCP baseline. No deployment is required.
resource "google_storage_bucket" "app_data" {
  name                        = "infraguard-synthetic-app-data"
  location                    = "ASIA-SOUTH1"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_compute_firewall" "https_from_corp" {
  name    = "synthetic-https-from-corp"
  network = "default"

  direction     = "INGRESS"
  source_ranges = ["10.10.0.0/16"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
