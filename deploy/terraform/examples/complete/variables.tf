variable "region" {
  description = "AWS Region that hosts the EKS cluster and all Khalifa resources."
  type        = string
}

variable "cluster_name" {
  description = "Existing EKS cluster that will run the Khalifa workloads."
  type        = string
}

variable "vpc_id" {
  description = "VPC that hosts Neptune and the EKS cluster."
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to reach Neptune."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the Neptune subnet group."
  type        = list(string)
}

variable "node_security_group_id" {
  description = "EKS node security group allowed to reach Neptune on 8182."
  type        = string
}

variable "oidc_provider_arn" {
  description = "EKS cluster OIDC provider ARN used for IRSA trust."
  type        = string
}

variable "name_prefix" {
  description = "Environment-specific prefix for all Khalifa resources (DNS-safe: lowercase letters, digits, hyphens)."
  type        = string

  validation {
    condition = (
      length(var.name_prefix) <= 32 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.name_prefix))
    )
    error_message = "name_prefix must be 1-32 lowercase alphanumeric or hyphen characters and cannot end with a hyphen."
  }
}

variable "namespace" {
  description = "Existing Kubernetes namespace for the release. Create it before the chart is installed, for example kubectl create namespace khalifa."
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
    condition     = length(trimspace(var.release_name)) > 0
    error_message = "release_name must not be empty."
  }
}

variable "home_account_id" {
  description = "12-digit AWS account that runs collection (the hub account)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.home_account_id))
    error_message = "home_account_id must be a 12-digit AWS account ID."
  }
}

variable "collection_account_ids" {
  description = "Approved member account IDs for organization collection. The home account is added automatically."
  type        = list(string)
  default     = []
}

variable "collection_parent_ids" {
  description = "Approved organization root or OU IDs for collection when the hub must discover accounts."
  type        = list(string)
  default     = []
}

variable "collection_regions" {
  description = "Regions the collectors are allowed to scan."
  type        = list(string)

  validation {
    condition     = length(var.collection_regions) > 0
    error_message = "collection_regions must contain at least one Region."
  }
}

variable "ui_base_url" {
  description = "Public UI origin used for Cognito callbacks and issue links, e.g. https://khalifa.example.com."
  type        = string
}

variable "image_digests" {
  description = "Digest references for the api, ui, and rule-runner images pushed to the module ECR repositories. The chart schema only accepts digest-pinned images; read them from ECR or the release workflow's artifacts."
  type = object({
    api         = string
    ui          = string
    rule_runner = string
  })

  validation {
    condition     = alltrue([for digest in values(var.image_digests) : can(regex("^sha256:[a-f0-9]{64}$", digest))])
    error_message = "image_digests must contain sha256:<64 hex characters> digests for api, ui, and rule_runner."
  }
}

variable "install_chart" {
  description = "Install the Helm release. Apply once with false to create the AWS resources and ECR repositories, push images, then apply again with true."
  type        = bool
  default     = true
}

variable "extra_chart_values" {
  description = "Additional Helm values merged last at the top level, for example ingress, autoscaling, or serviceMonitor. Keys override the defaults for that key; include the generated keys (for example image) when overriding a component map."
  type        = any
  default     = {}
}

variable "github_repository" {
  description = "GitHub repository (owner/name) allowed to publish release images through the registry module."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in owner/name form."
  }
}

variable "github_oidc_subject_prefix" {
  description = "Override for the GitHub OIDC sub prefix, for example GitHub's immutable repo:owner@ID/name@ID form. Defaults to the github_repository value with a repo: prefix."
  type        = string
  default     = ""
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
}

variable "cloudtrail_logs_kms_key_arn" {
  description = "KMS key that encrypts the trail objects. The analyzer role is allowed kms:Decrypt on it; the key policy in the owning account must allow the role as well."
  type        = string
  default     = ""
}

variable "analysis_days" {
  description = "CloudTrail lookback window in days for usage telemetry."
  type        = number
  default     = 90
}

variable "securityhub_reader_role_arn" {
  description = "Audit-account role the compliance job assumes to read Security Hub for CIS reconciliation. Empty disables reconciliation."
  type        = string
  default     = ""
}

variable "dspm_bucket_allowlist" {
  description = "Buckets the DSPM scanner may read object content from. Empty keeps the historical all-buckets grant."
  type        = list(string)
  default     = []
}

variable "macie_enabled" {
  description = "Whether the DSPM scanner consults Macie findings as the primary engine."
  type        = bool
  default     = false
}

variable "allow_public_https_egress" {
  description = "Allow workload pods outbound TCP 443 to reach AWS public API endpoints until interface VPC endpoints exist."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Additional tags for all created resources."
  type        = map(string)
  default     = {}
}
