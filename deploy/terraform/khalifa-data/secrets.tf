resource "random_password" "collector_external_id" {
  length  = 32
  special = false
}

resource "random_password" "graph_writer_token" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "runtime" {
  name                    = "${local.name}/runtime"
  recovery_window_in_days = 30
  kms_key_id              = aws_kms_key.this.arn

  tags = merge(var.tags, { Name = "${local.name}-runtime" })
}

resource "aws_secretsmanager_secret_version" "runtime" {
  secret_id = aws_secretsmanager_secret.runtime.id
  secret_string = jsonencode({
    COLLECTOR_EXTERNAL_ID = random_password.collector_external_id.result
    GRAPH_WRITER_TOKEN    = random_password.graph_writer_token.result
  })
}

resource "random_password" "neptune" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "neptune" {
  name                    = "${local.name}/neptune-auth"
  recovery_window_in_days = 30
  kms_key_id              = aws_kms_key.this.arn

  tags = merge(var.tags, { Name = "${local.name}-neptune-auth" })
}

resource "aws_secretsmanager_secret_version" "neptune" {
  secret_id = aws_secretsmanager_secret.neptune.id
  secret_string = jsonencode({
    username = "neptune_user"
    password = random_password.neptune.result
  })
}
