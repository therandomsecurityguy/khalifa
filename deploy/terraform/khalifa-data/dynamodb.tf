resource "aws_dynamodb_table" "issues" {
  name         = "${local.name}-issues"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  range_key    = "ruleId"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "ruleId"
    type = "S"
  }

  attribute {
    name = "updatedAt"
    type = "S"
  }

  attribute {
    name = "status"
    type = "S"
  }

  attribute {
    name = "createdAt"
    type = "S"
  }

  global_secondary_index {
    name            = "RuleIdIndex"
    hash_key        = "ruleId"
    range_key       = "updatedAt"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "status"
    range_key       = "updatedAt"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "StatusCreatedIndex"
    hash_key        = "status"
    range_key       = "createdAt"
    projection_type = "ALL"
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-issues" })
}

resource "aws_dynamodb_table" "evidence" {
  name         = "${local.name}-evidence"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "controlId"
  range_key    = "resourceId"

  attribute {
    name = "controlId"
    type = "S"
  }

  attribute {
    name = "resourceId"
    type = "S"
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-evidence" })
}

resource "aws_dynamodb_table" "reports" {
  name         = "${local.name}-reports"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "framework"
  range_key    = "generatedAt"

  attribute {
    name = "framework"
    type = "S"
  }

  attribute {
    name = "generatedAt"
    type = "S"
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-reports" })
}

resource "aws_dynamodb_table" "posture_trends" {
  name         = "${local.name}-posture-trends"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "metric"
  range_key    = "date"

  attribute {
    name = "metric"
    type = "S"
  }

  attribute {
    name = "date"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-posture-trends" })
}

resource "aws_dynamodb_table" "access_analyzer" {
  name         = "${local.name}-access-analyzer"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "principalArn"
  range_key    = "eventSourceEventName"

  attribute {
    name = "principalArn"
    type = "S"
  }

  attribute {
    name = "eventSourceEventName"
    type = "S"
  }

  attribute {
    name = "lastUsed"
    type = "S"
  }

  global_secondary_index {
    name            = "ActionIndex"
    hash_key        = "eventSourceEventName"
    range_key       = "lastUsed"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-access-analyzer" })
}

resource "aws_dynamodb_table" "least_privilege" {
  name         = "${local.name}-least-privilege"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "accountId"
  range_key    = "principalArn"

  attribute {
    name = "accountId"
    type = "S"
  }

  attribute {
    name = "principalArn"
    type = "S"
  }

  attribute {
    name = "riskLevel"
    type = "S"
  }

  attribute {
    name = "removedActionCount"
    type = "N"
  }

  global_secondary_index {
    name            = "RiskLevelIndex"
    hash_key        = "riskLevel"
    range_key       = "removedActionCount"
    projection_type = "ALL"
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-least-privilege" })
}

# Observed reachability for the flow-log-analyzer: one row per network
# interface, overwritten each run and expired by TTL. The collector reads it
# when it collects instances.
resource "aws_dynamodb_table" "traffic_observations" {
  name         = "${local.name}-traffic-observations"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "interface_id"

  attribute {
    name = "interface_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-traffic-observations" })
}

# Customer threat-intel indicators for the rule runner's matching and the
# threat-intel-import CronJob's writes; TTL is what makes an indicator stale.
resource "aws_dynamodb_table" "threat_indicators" {
  name         = "${local.name}-threat-indicators"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "indicator"

  attribute {
    name = "indicator"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.this.arn
  }

  tags = merge(var.tags, { Name = "${local.name}-threat-indicators" })
}
