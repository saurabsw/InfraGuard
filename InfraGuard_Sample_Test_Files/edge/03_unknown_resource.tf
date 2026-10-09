# A syntactically valid resource type that InfraGuard may not support.
resource "examplecorp_unknown_service" "sample" {
  name             = "synthetic-unknown-resource"
  public_access    = true
  encryption       = false
}
