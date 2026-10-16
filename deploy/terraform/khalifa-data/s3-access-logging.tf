# Access logging for the source buckets this module owns. The destination
# bucket lives in this module's account and Region and does not log to itself;
# organization CloudTrail data events audit access to the logs.
#
# S3 server access logging with ACLs disabled (BucketOwnerEnforced) requires a
# bucket policy that lets the logging service principal write the log objects,
# so that grant lives on the destination below. The destination uses SSE-S3:
# the log delivery principal would also need kms:GenerateDataKey for a
# customer-managed key, which the module's CMK key policy does not grant.

resource "aws_s3_bucket" "access_logs" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = "${local.name}-access-logs"

  tags = merge(var.tags, { Name = "${local.name}-access-logs" })
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.access_logs[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RequireTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.access_logs[0].arn,
          "${aws_s3_bucket.access_logs[0].arn}/*",
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "AllowS3ServerAccessLogging"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs[0].arn}/s3/*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.athena_results[0].arn }
        }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

resource "aws_s3_bucket_logging" "athena_results_access_logging" {
  count         = length(aws_s3_bucket.athena_results)
  bucket        = aws_s3_bucket.athena_results[count.index].id
  target_bucket = aws_s3_bucket.access_logs[0].id
  target_prefix = "s3/${aws_s3_bucket.athena_results[count.index].id}/"
}
