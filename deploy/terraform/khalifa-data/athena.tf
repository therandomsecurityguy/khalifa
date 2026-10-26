# Athena over the organization CloudTrail for the cloudtrail-analyzer CronJob.
# Everything here is created only when cloudtrail_logs_bucket is set. The trail
# bucket and its KMS key live in the account that owns the trail; that account
# must allow the analyzer role to read them (see README) before the CronJob is
# unsuspended.

locals {
  cloudtrail_enabled = var.cloudtrail_logs_bucket != ""
  cloudtrail_logs_root = join("/", compact([
    "s3://${var.cloudtrail_logs_bucket}",
    trim(var.cloudtrail_logs_prefix, "/"),
    "AWSLogs",
    var.cloudtrail_organization_id,
  ]))
  athena_results_location = local.cloudtrail_enabled ? "s3://${aws_s3_bucket.athena_results[0].bucket}/results/" : ""

  # 500 GiB per query. Ninety days of an organization trail is tens of GiB, so
  # this only stops a runaway query, not a normal run.
  athena_bytes_scanned_cutoff = 500 * 1024 * 1024 * 1024

  # The flow-log analyzer reuses the CloudTrail database and workgroup, so it
  # is enabled only alongside them.
  flow_logs_enabled = local.cloudtrail_enabled && var.flow_logs_bucket != ""
  flow_logs_root = join("/", compact([
    "s3://${var.flow_logs_bucket}",
    trim(var.flow_logs_prefix, "/"),
    "AWSLogs",
    var.flow_logs_organization_id,
  ]))

  # Standard VPC flow-log v5 default fields (space-delimited, 14 groups). The
  # second group (account-id) is skipped: account_id is a partition key, so the
  # RegexSerDe output format maps the remaining groups to the columns.
  flow_logs_columns = [
    { name = "version", type = "int" },
    { name = "interface_id", type = "string" },
    { name = "srcaddr", type = "string" },
    { name = "dstaddr", type = "string" },
    { name = "srcport", type = "int" },
    { name = "dstport", type = "int" },
    { name = "protocol", type = "bigint" },
    { name = "packets", type = "bigint" },
    { name = "bytes", type = "bigint" },
    { name = "start", type = "bigint" },
    { name = "end", type = "bigint" },
    { name = "action", type = "string" },
    { name = "log_status", type = "string" },
  ]

  # Standard CloudTrail record layout, as documented for Athena.
  cloudtrail_columns = [
    { name = "eventversion", type = "string" },
    {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>,ec2roledelivery:string,webidfederationdata:struct<federatedprovider:string,attributes:map<string,string>>>>"
    },
    { name = "eventtime", type = "string" },
    { name = "eventsource", type = "string" },
    { name = "eventname", type = "string" },
    { name = "awsregion", type = "string" },
    { name = "sourceipaddress", type = "string" },
    { name = "useragent", type = "string" },
    { name = "errorcode", type = "string" },
    { name = "errormessage", type = "string" },
    { name = "requestparameters", type = "string" },
    { name = "responseelements", type = "string" },
    { name = "additionaleventdata", type = "string" },
    { name = "requestid", type = "string" },
    { name = "eventid", type = "string" },
    { name = "resources", type = "array<struct<arn:string,accountid:string,type:string>>" },
    { name = "eventtype", type = "string" },
    { name = "apiversion", type = "string" },
    { name = "readonly", type = "string" },
    { name = "recipientaccountid", type = "string" },
    { name = "serviceeventdetails", type = "string" },
    { name = "sharedeventid", type = "string" },
    { name = "vpcendpointid", type = "string" },
    { name = "tlsdetails", type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>" },
  ]
}

# The trail is multi-Region, so the region partition enumerates every Region.
data "aws_regions" "all" {
  count       = local.cloudtrail_enabled ? 1 : 0
  all_regions = true
}

resource "aws_s3_bucket" "athena_results" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = "${local.name}-athena-results"

  tags = merge(var.tags, { Name = "${local.name}-athena-results" })
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "athena_results" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

# Query results are scratch data the analyzer reads once through the Athena API.
resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  rule {
    id     = "expire-results"
    status = "Enabled"

    filter {}

    expiration {
      days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "athena_results" {
  count  = local.cloudtrail_enabled ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "RequireTls"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.athena_results[0].arn,
        "${aws_s3_bucket.athena_results[0].arn}/*",
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.athena_results]
}

resource "aws_athena_workgroup" "cloudtrail" {
  count = local.cloudtrail_enabled ? 1 : 0
  name  = "${local.name}-cloudtrail"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = local.athena_bytes_scanned_cutoff

    result_configuration {
      output_location = local.athena_results_location

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.this.arn
      }
    }
  }

  force_destroy = true

  tags = merge(var.tags, { Name = "${local.name}-cloudtrail" })
}

resource "aws_glue_catalog_database" "cloudtrail" {
  count = local.cloudtrail_enabled ? 1 : 0
  # Athena identifiers cannot contain hyphens.
  name        = "${join("_", split("-", local.name))}_cloudtrail"
  description = "Organization CloudTrail for the Khalifa cloudtrail-analyzer"

  tags = var.tags
}

# Partition projection over account / Region / day, so the analyzer's
# log_date predicate reads only the days in its window instead of the whole
# trail. The account list is the collection scope, which is the population the
# analyzer reports on.
resource "aws_glue_catalog_table" "cloudtrail_logs" {
  count         = local.cloudtrail_enabled ? 1 : 0
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.cloudtrail[0].name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                            = "TRUE"
    classification                      = "cloudtrail"
    "projection.enabled"                = "true"
    "projection.account_id.type"        = "enum"
    "projection.account_id.values"      = join(",", local.collection_account_ids)
    "projection.region.type"            = "enum"
    "projection.region.values"          = join(",", sort(data.aws_regions.all[0].names))
    "projection.log_date.type"          = "date"
    "projection.log_date.range"         = "${var.cloudtrail_partition_start},NOW"
    "projection.log_date.format"        = "yyyy/MM/dd"
    "projection.log_date.interval"      = "1"
    "projection.log_date.interval.unit" = "DAYS"
    "storage.location.template"         = "${local.cloudtrail_logs_root}/$${account_id}/CloudTrail/$${region}/$${log_date}"
  }

  partition_keys {
    name = "account_id"
    type = "string"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "log_date"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.cloudtrail_logs_root}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "cloudtrail"
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
      parameters            = { "serialization.format" = "1" }
    }

    dynamic "columns" {
      for_each = local.cloudtrail_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# VPC flow logs for the flow-log-analyzer CronJob, same layout conventions as
# the CloudTrail table above (and the same database/workgroup). Only created
# when flow_logs_bucket is set alongside cloudtrail_logs_bucket.
resource "aws_glue_catalog_table" "vpc_flow_logs" {
  count         = local.flow_logs_enabled ? 1 : 0
  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.cloudtrail[0].name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                            = "TRUE"
    classification                      = "vpc-flow-logs"
    "projection.enabled"                = "true"
    "projection.account_id.type"        = "enum"
    "projection.account_id.values"      = join(",", local.collection_account_ids)
    "projection.region.type"            = "enum"
    "projection.region.values"          = join(",", sort(data.aws_regions.all[0].names))
    "projection.log_date.type"          = "date"
    "projection.log_date.range"         = "${var.cloudtrail_partition_start},NOW"
    "projection.log_date.format"        = "yyyy/MM/dd"
    "projection.log_date.interval"      = "1"
    "projection.log_date.interval.unit" = "DAYS"
    "storage.location.template"         = "${local.flow_logs_root}/$${account_id}/vpcflowlogs/$${region}/$${log_date}"
  }

  partition_keys {
    name = "account_id"
    type = "string"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "log_date"
    type = "string"
  }

  storage_descriptor {
    location      = "${local.flow_logs_root}/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "vpc-flow-logs"
      serialization_library = "org.apache.hadoop.hive.serde2.RegexSerDe"
      parameters = {
        input.regex   = "^(\\d+) (\\S+) (\\S+) (\\S+) (\\S+) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) (\\d+) (\\S+) (\\S+)$"
        output.format = "%1%3%4%5%6%7%8%9%10%11%12%13%14"
      }
    }

    dynamic "columns" {
      for_each = local.flow_logs_columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}
