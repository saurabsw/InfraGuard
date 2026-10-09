# Insecure GCP Terraform Infrastructure Fixture
# Violates IG-GCP-001, IG-GCP-002, IG-GCP-003, IG-GCP-004, IG-GCP-005, IG-GCP-006, IG-GCP-007

resource "google_storage_bucket" "insecure_bucket" {
  name                        = "insecure-bucket-123"
  location                    = "US"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
}

resource "google_storage_bucket_iam_binding" "public_viewer" {
  bucket = google_storage_bucket.insecure_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers"
  ]
}

resource "google_compute_firewall" "insecure_firewall" {
  name    = "insecure-firewall"
  network = "default"

  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  allow {
    protocol = "all"
  }
}

resource "google_project_iam_binding" "public_owner" {
  project = "my-gcp-project"
  role    = "roles/owner"
  members = [
    "allAuthenticatedUsers"
  ]
}
