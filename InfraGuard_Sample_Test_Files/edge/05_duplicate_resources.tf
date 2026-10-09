# Two resources with similar names help test resource identity and duplicate handling.
resource "aws_s3_bucket" "logs_a" {
  bucket = "infraguard-synthetic-logs-a"
}
resource "aws_s3_bucket" "logs_b" {
  bucket = "infraguard-synthetic-logs-b"
}
