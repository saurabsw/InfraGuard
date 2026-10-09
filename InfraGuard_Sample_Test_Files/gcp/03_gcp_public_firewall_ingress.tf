# Intentionally insecure fixture: broad ingress across all ports/protocols.
resource "google_compute_firewall" "broad_ingress" {
  name    = "synthetic-broad-ingress"
  network = "default"

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "all"
  }
}
