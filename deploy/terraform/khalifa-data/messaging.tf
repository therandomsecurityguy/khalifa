resource "aws_sqs_queue" "incremental_dlq" {
  name                        = "${local.name}-incremental-dlq.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  kms_master_key_id           = aws_kms_key.this.arn

  tags = merge(var.tags, { Name = "${local.name}-incremental-dlq" })
}

resource "aws_sqs_queue" "incremental" {
  name                        = "${local.name}-incremental.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  kms_master_key_id           = aws_kms_key.this.arn
  visibility_timeout_seconds  = 300
  message_retention_seconds   = 345600

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.incremental_dlq.arn
    maxReceiveCount     = 3
  })

  tags = merge(var.tags, { Name = "${local.name}-incremental" })
}

resource "aws_sqs_queue_policy" "incremental" {
  queue_url = aws_sqs_queue.incremental.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonServiceSend"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.incremental.arn
        Condition = {
          Bool = { "aws:PrincipalIsAWSService" = "false" }
        }
      },
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.incremental.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "issues" {
  name              = "${local.name}-issues"
  kms_master_key_id = aws_kms_key.this.arn

  tags = merge(var.tags, { Name = "${local.name}-issues" })
}
