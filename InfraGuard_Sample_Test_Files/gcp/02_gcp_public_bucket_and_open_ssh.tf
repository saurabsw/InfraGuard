# Intentionally insecure fixture: public IAM member and internet-wide SSH.
resource "google_storage_bucket" "public_data" {
  name                        = "infraguard-synthetic-public-data"
  location                    = "ASIA-SOUTH1"
  uniform_bucket_level_access = false
  public_access_prevention    = "inherited"
}

resource "google_storage_bucket_iam_member" "public_reader" {
  bucket = google_storage_bucket.public_data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_compute_firewall" "open_ssh" {
  name    = "synthetic-open-ssh"
  network = "default"

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
