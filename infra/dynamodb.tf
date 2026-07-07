# DynamoDB table for Security Hub Agent execution history (TTL 90d, PITR enabled)

resource "aws_dynamodb_table" "history" {
  name         = "security-hub-agent-history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "run_date"
  range_key    = "executed_at"

  attribute {
    name = "run_date"
    type = "S"
  }

  attribute {
    name = "executed_at"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }
}
