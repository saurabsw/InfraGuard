# Synthetic secure baseline. No deployment is required.
resource "aws_s3_bucket" "app_logs" {
  bucket = "infraguard-synthetic-app-logs"
}

resource "aws_s3_bucket_public_access_block" "app_logs" {
  bucket                  = aws_s3_bucket.app_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app_logs" {
  bucket = aws_s3_bucket.app_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "app" {
  name        = "synthetic-app"
  description = "Synthetic app security group"
  ingress {
    description = "HTTPS from approved range"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.10.0.0/16"]
  }
}
