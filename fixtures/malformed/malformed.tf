# Malformed Terraform file with broken syntax
resource "aws_s3_bucket" "broken" {
  bucket = "unclosed string
  tags = {
