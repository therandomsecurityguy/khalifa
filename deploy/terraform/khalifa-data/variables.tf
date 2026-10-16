variable "name_prefix" {
  description = "Environment-specific prefix for Khalifa data-plane resources."
  type        = string

  validation {
    condition = (
      length(var.name_prefix) <= 32 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.name_prefix))
    )
    error_message = "name_prefix must be 1-32 lowercase alphanumeric or hyphen characters and cannot end with a hyphen."
  }
}

variable "vpc_id" {
  description = "VPC that hosts Neptune and the EKS cluster."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to reach Neptune."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be a valid CIDR block."
  }
}

variable "private_subnet_ids" {
  description = "Private subnets for the Neptune subnet group."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Neptune requires at least two private subnets."
  }
}

variable "node_security_group_id" {
  description = "EKS node security group allowed to reach Neptune on 8182."
  type        = string
}

variable "oidc_provider_arn" {
  description = "EKS cluster OIDC provider ARN used for IRSA trust."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:oidc-provider/.+", var.oidc_provider_arn))
    error_message = "oidc_provider_arn must be an IAM OIDC provider ARN."
  }
}

variable "namespace" {
  description = "Kubernetes namespace for workload ServiceAccounts."
  type        = string
  default     = "khalifa"

  validation {
    condition     = length(trimspace(var.namespace)) > 0
    error_message = "namespace must not be empty."
  }
}

variable "release_name" {
  description = "Helm release name used to derive ServiceAccount names."
  type        = string
  default     = "khalifa"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.release_name))
    error_message = "release_name must be a DNS-1123 label."
  }
}

variable "home_account_id" {
  description = "12-digit AWS account that runs collection."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.home_account_id))
    error_message = "home_account_id must be a 12-digit AWS account ID."
  }
}

variable "securityhub_reader_role_arn" {
  description = "Audit account role the compliance job assumes to read Security Hub for CIS reconciliation (SEC-3254). Empty: no grant."
  type        = string
  default     = ""

  validation {
    condition     = var.securityhub_reader_role_arn == "" || can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.securityhub_reader_role_arn))
    error_message = "securityhub_reader_role_arn must be empty or an IAM role ARN."
  }
}

variable "collection_account_ids" {
  description = "Approved member account IDs for organization collection."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for account_id in var.collection_account_ids : can(regex("^[0-9]{12}$", account_id))
    ])
    error_message = "collection_account_ids must contain only 12-digit AWS account IDs."
  }
}

variable "collection_parent_ids" {
  description = "Approved organization parent IDs for collection."
  type        = list(string)
  default     = []
}

variable "collection_regions" {
  description = "Regions the collectors are allowed to scan."
  type        = list(string)
  default     = ["us-west-2"]
}

variable "ui_base_url" {
  description = "Public UI origin used for Cognito callbacks and issue links."
  type        = string

  validation {
    condition     = can(regex("^https://", var.ui_base_url))
    error_message = "ui_base_url must be an https URL."
  }
}

variable "dspm_bucket_allowlist" {
  description = "Buckets the DSPM scanner may read object content from. Empty keeps the historical all-buckets grant."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for bucket in var.dspm_bucket_allowlist : can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", bucket))
    ])
    error_message = "dspm_bucket_allowlist must contain valid S3 bucket names."
  }
}

variable "collector_role_name" {
  description = "IAM role name assumed in member accounts."
  type        = string
  default     = "SecurityGraphCollectorRole"
}

variable "analysis_days" {
  description = "CloudTrail lookback window in days for usage telemetry."
  type        = number
  default     = 90

  validation {
    condition     = var.analysis_days >= 1 && var.analysis_days <= 365
    error_message = "analysis_days must be between 1 and 365."
  }
}

variable "cloudtrail_logs_bucket" {
  description = "S3 bucket that receives the organization CloudTrail. Empty leaves the CloudTrail analyzer without Athena resources or permissions."
  type        = string
  default     = ""
}

variable "cloudtrail_logs_prefix" {
  description = "Key prefix the trail writes under, before AWSLogs/. Empty when the trail writes to the bucket root."
  type        = string
  default     = ""
}

variable "cloudtrail_organization_id" {
  description = "Organization id (o-...) that appears in an organization trail's key path. Empty for a single-account trail."
  type        = string
  default     = ""

  validation {
    condition     = var.cloudtrail_organization_id == "" || can(regex("^o-[a-z0-9]{10,32}$", var.cloudtrail_organization_id))
    error_message = "cloudtrail_organization_id must be empty or an AWS Organizations id (o-...)."
  }
}

variable "cloudtrail_logs_kms_key_arn" {
  description = "KMS key that encrypts the trail objects. The analyzer role is allowed kms:Decrypt on it; the key policy in the owning account must allow the role as well."
  type        = string
  default     = ""
}

variable "cloudtrail_partition_start" {
  description = "First day (yyyy/MM/dd) the CloudTrail partition projection covers."
  type        = string
  default     = "2025/01/01"

  validation {
    condition     = can(regex("^[0-9]{4}/[0-9]{2}/[0-9]{2}$", var.cloudtrail_partition_start))
    error_message = "cloudtrail_partition_start must be yyyy/MM/dd."
  }
}

variable "allow_public_https_egress" {
  description = "Allow workload pods outbound TCP 443 to the internet. Required for AWS public API endpoints (DynamoDB, SQS, Secrets Manager, Cognito, S3, Athena, Macie) until interface VPC endpoints are provisioned; once endpoints exist, set false and rely on VPC-CIDR egress."
  type        = bool
  default     = true
}

variable "private_route_table_ids" {
  description = "Private route tables for the S3 gateway endpoint. Empty leaves S3 traffic on the default route (weaker isolation)."
  type        = list(string)
  default     = []
}

variable "dspm_scan_mode" {
  description = "DSPM scan mode for the secret scanner: tagged-only samples buckets tagged dspm-scan=true, all samples every bucket, off disables sampling."
  type        = string
  default     = "tagged-only"

  validation {
    condition     = contains(["tagged-only", "all", "off"], var.dspm_scan_mode)
    error_message = "dspm_scan_mode must be one of tagged-only, all, off."
  }
}

variable "macie_enabled" {
  description = "Whether the DSPM scanner consults Macie findings as the primary engine."
  type        = bool
  default     = false
}

variable "neptune_min_capacity" {
  description = "Neptune Serverless minimum NCUs. Measured in production: at 2.5 NCU even a single-vertex write fails with MemoryLimitExceededException or ConcurrentModificationException, and writes also fail for a few minutes during every scale transition, so the floor must hold the capacity the collector bursts need."
  type        = number
  default     = 16

  validation {
    condition     = var.neptune_min_capacity >= 1 && var.neptune_min_capacity <= var.neptune_max_capacity
    error_message = "neptune_min_capacity must be at least 1 and no greater than neptune_max_capacity."
  }
}

variable "neptune_max_capacity" {
  description = "Neptune Serverless maximum NCUs."
  type        = number
  default     = 32
}

variable "tags" {
  description = "Additional tags for Khalifa data-plane resources."
  type        = map(string)
  default     = {}
}
