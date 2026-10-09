# Intentionally insecure fixture: public database and storage encryption disabled.
resource "aws_db_instance" "legacy" {
  identifier              = "infraguard-synthetic-db"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "synthetic_user"
  password                = "NOT_A_REAL_PASSWORD_REPLACE_ME"
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
}
