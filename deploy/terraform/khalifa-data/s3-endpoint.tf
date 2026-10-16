# Optional S3 gateway endpoint so scanner pods reach S3 over the AWS private
# network. Gateway endpoints attach to route tables, which are owned by the
# external VPC module, so the deployment supplies private_route_table_ids. Without
# them S3 traffic follows the default route and isolation is weaker.

resource "aws_vpc_endpoint" "s3_gateway" {
  count             = length(var.private_route_table_ids) > 0 ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.private_route_table_ids

  tags = merge(var.tags, {
    Name = "${local.name}-s3-gateway"
  })
}

# Endpoint policies intersect with IAM identity policies, so every S3 call a
# Khalifa workload makes through this endpoint needs an Allow here. Reads:
# the DSPM scanner and collectors. Writes: the CloudTrail analyzer uploads
# Athena results. Without the write statement, gateway-endpoint policies
# (which always restrict) would break analyzer result uploads.
resource "aws_vpc_endpoint_policy" "s3_gateway" {
  count           = length(var.private_route_table_ids) > 0 ? 1 : 0
  vpc_endpoint_id = aws_vpc_endpoint.s3_gateway[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid       = "S3ReadViaEndpoint"
          Effect    = "Allow"
          Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
          Action = [
            "s3:ListBucket",
            "s3:GetObject",
            "s3:GetBucketLocation",
            "s3:ListAllMyBuckets",
          ]
          Resource = ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]
        },
      ],
      local.cloudtrail_enabled ? [
        {
          Sid       = "S3AnalyzerResultsWriteViaEndpoint"
          Effect    = "Allow"
          Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
          Action = [
            "s3:PutObject",
            "s3:AbortMultipartUpload",
            "s3:ListBucket",
            "s3:GetBucketLocation",
          ]
          Resource = [
            aws_s3_bucket.athena_results[0].arn,
            "${aws_s3_bucket.athena_results[0].arn}/*",
          ]
        },
      ] : []
    )
  })
}

output "s3_gateway_endpoint_id" {
  description = "S3 gateway endpoint id for the Khalifa VPC (empty when no route tables were supplied)."
  value       = length(var.private_route_table_ids) > 0 ? aws_vpc_endpoint.s3_gateway[0].id : ""
}