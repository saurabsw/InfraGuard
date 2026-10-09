# Intentionally malformed HCL: missing closing brace and incomplete expression.
resource "aws_s3_bucket" "broken" {
  bucket = 
  acl    = "public-read"
