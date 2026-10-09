# Secure AWS Terraform Infrastructure Fixture
# Passes all applicable AWS security checks

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-production-bucket"

  logging {
    target_bucket = "log-bucket"
    target_prefix = "log/"
  }
}

resource "aws_s3_bucket_policy" "restricted_policy" {
  bucket = aws_s3_bucket.secure_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "StrictOrgAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:root"
        }
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::secure-production-bucket/*"
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "enabled_block" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_security_group" "restricted_sg" {
  name        = "secure-sg"
  description = "Restricted ingress only"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }
}

resource "aws_db_instance" "secure_rds" {
  allocated_storage   = 50
  engine              = "postgres"
  instance_class      = "db.r5.large"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_ebs_volume" "secure_ebs" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}

resource "aws_iam_policy" "scoped_iam" {
  name = "scoped-access-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::secure-production-bucket/reports/*"
      }
    ]
  })
}
