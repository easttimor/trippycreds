resource "aws_dynamodb_table" "canary_keys" {
  name                        = "canary-keys"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "access_key_id"
  deletion_protection_enabled = true

  attribute {
    name = "access_key_id"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  global_secondary_index {
    name            = "status-index"
    hash_key        = "status"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_dynamodb_table" "canary_events" {
  name                        = "canary-events"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "access_key_id"
  range_key                   = "event_time"
  deletion_protection_enabled = true

  attribute {
    name = "access_key_id"
    type = "S"
  }

  attribute {
    name = "event_time"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

# Registry of AWS principals trusted to call the cross-account service API
# (POST /service/claim) without an operator in the loop - see
# trippycreds/trusted_principals.py and DESIGN.md's "Cross-account service
# claims" section. PK is the (normalized) IAM role/user ARN being trusted.
resource "aws_dynamodb_table" "trusted_principals" {
  name                        = "trusted-principals"
  billing_mode                = "PAY_PER_REQUEST"
  hash_key                    = "principal_arn"
  deletion_protection_enabled = true

  attribute {
    name = "principal_arn"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}
