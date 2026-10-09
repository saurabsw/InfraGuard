# Intentionally insecure fixture: public S3 ACL and internet-wide SSH.
resource "aws_s3_bucket" "public_uploads" {
  bucket = "infraguard-synthetic-public-uploads"
}

resource "aws_s3_bucket_acl" "public_uploads" {
  bucket = aws_s3_bucket.public_uploads.id
  acl    = "public-read"
}

resource "aws_security_group" "admin" {
  name        = "synthetic-admin-open-ssh"
  description = "Intentionally insecure test fixture"
  ingress {
    description = "SSH from anywhere - intentionally insecure"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
