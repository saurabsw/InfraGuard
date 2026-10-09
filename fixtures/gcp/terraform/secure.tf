# Secure GCP Terraform Infrastructure Fixture
# Complies with all GCP guardrails

resource "google_storage_bucket" "secure_bucket" {
  name                        = "secure-bucket-123"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
}

resource "google_storage_bucket_iam_binding" "private_viewer" {
  bucket = google_storage_bucket.secure_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "user:alice@example.com"
  ]
}

resource "google_compute_firewall" "secure_firewall" {
  name    = "secure-firewall"
  network = "default"

  source_ranges = ["10.0.0.0/16"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_project_iam_binding" "scoped_project_iam" {
  project = "my-gcp-project"
  role    = "roles/viewer"
  members = [
    "group:devs@example.com"
  ]
}
