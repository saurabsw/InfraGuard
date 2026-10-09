# Insecure AWS Terraform Infrastructure Fixture
# Violates IG-AWS-001, IG-AWS-002, IG-AWS-003, IG-AWS-004, IG-AWS-005, IG-AWS-006, IG-AWS-007, IG-AWS-008, IG-AWS-009, IG-IAM-001, IG-AWS-010

resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "insecure-data-bucket"
}

resource "aws_s3_bucket_policy" "public_read_write" {
  bucket = aws_s3_bucket.insecure_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWrite"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "arn:aws:s3:::insecure-data-bucket/*"
      }
    ]
  })
}

resource "aws_s3_bucket_public_access_block" "disabled_block" {
  bucket = aws_s3_bucket.insecure_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "open_all" {
  name        = "open-security-group"
  description = "Allows SSH, RDP, and wildcard access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "insecure_rds" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_ebs_volume" "unencrypted_ebs" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false
}

resource "aws_iam_policy" "admin_wildcard" {
  name = "overly-permissive-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
