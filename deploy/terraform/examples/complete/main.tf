data "aws_caller_identity" "current" {}

data "aws_eks_cluster" "this" {
  name = var.cluster_name
}

provider "aws" {
  region = var.region
}

provider "helm" {
  kubernetes = {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", var.cluster_name, "--region", var.region]
    }
  }
}

locals {
  service_account_roles = {
    api                   = module.khalifa_data.workload_role_arns["api"]
    ui                    = module.khalifa_data.workload_role_arns["ui"]
    ruleRunner            = module.khalifa_data.workload_role_arns["rule-runner"]
    organizationCollector = module.khalifa_data.workload_role_arns["org-collector"]
    incrementalCollector  = module.khalifa_data.workload_role_arns["incremental"]
    graphWriter           = module.khalifa_data.workload_role_arns["graph-writer"]
    compliance            = module.khalifa_data.workload_role_arns["compliance"]
    cloudtrailAnalyzer    = module.khalifa_data.workload_role_arns["cloudtrail-analyzer"]
    dspmScanner           = module.khalifa_data.workload_role_arns["dspm-scanner"]
    policyEvaluator       = module.khalifa_data.workload_role_arns["policy-evaluator"]
    leastPrivilegeSweep   = module.khalifa_data.workload_role_arns["least-privilege-sweep"]
  }

  api_image         = "${module.khalifa_registry.repositories["api"].url}:${var.image_tag}"
  ui_image          = "${module.khalifa_registry.repositories["ui"].url}:${var.image_tag}"
  rule_runner_image = "${module.khalifa_registry.repositories["rule-runner"].url}:${var.image_tag}"

  # Every collector-style workload runs the rule-runner image; the runtime
  # command selects the entrypoint.
  chart_values = merge(
    module.khalifa_data.helm_values,
    {
      commonLabels = { environment = var.name_prefix }
      serviceAccounts = {
        for key, role_arn in local.service_account_roles :
        key => { annotations = { "eks.amazonaws.com/role-arn" = role_arn } }
      }
      api                   = { image = local.api_image }
      ui                    = { image = local.ui_image }
      ruleRunner            = { image = local.rule_runner_image }
      compliance            = { image = local.rule_runner_image }
      graphWriter           = { image = local.rule_runner_image }
      organizationCollector = { image = local.rule_runner_image }
      incrementalCollector  = { image = local.rule_runner_image }
      cloudtrailAnalyzer    = { image = local.rule_runner_image }
      dspmScanner           = { image = local.rule_runner_image }
      policyEvaluator       = { image = local.rule_runner_image }
      leastPrivilegeSweep   = { image = local.rule_runner_image }
      # COLLECTOR_EXTERNAL_ID and GRAPH_WRITER_TOKEN come from Secrets Manager
      # through External Secrets; they are never chart values or state.
      externalSecrets = {
        enabled    = true
        targetName = module.khalifa_data.runtime_secret_name
        secretStore = {
          service = "SecretsManager"
          region  = var.region
          roleArn = aws_iam_role.external_secrets.arn
        }
        data = [
          {
            secretKey = "COLLECTOR_EXTERNAL_ID"
            remoteRef = {
              key      = module.khalifa_data.runtime_secret_name
              property = "COLLECTOR_EXTERNAL_ID"
            }
          },
          {
            secretKey = "GRAPH_WRITER_TOKEN"
            remoteRef = {
              key      = module.khalifa_data.runtime_secret_name
              property = "GRAPH_WRITER_TOKEN"
            }
          },
        ]
        mountIn = [
          "organizationCollector",
          "incrementalCollector",
          "graphWriter",
          "cloudtrailAnalyzer",
          "dspmScanner",
        ]
      }
    },
    var.extra_chart_values
  )
}

module "khalifa_registry" {
  source = "../../khalifa-registry"

  name_prefix                = var.name_prefix
  github_repository          = var.github_repository
  github_oidc_subject_prefix = var.github_oidc_subject_prefix
  tags                       = var.tags
}

module "khalifa_data" {
  source = "../../khalifa-data"

  name_prefix            = var.name_prefix
  vpc_id                 = var.vpc_id
  vpc_cidr               = var.vpc_cidr
  private_subnet_ids     = var.private_subnet_ids
  node_security_group_id = var.node_security_group_id
  oidc_provider_arn      = var.oidc_provider_arn

  namespace    = var.namespace
  release_name = var.release_name

  home_account_id        = var.home_account_id
  collection_account_ids = var.collection_account_ids
  collection_parent_ids  = var.collection_parent_ids
  collection_regions     = var.collection_regions
  ui_base_url            = var.ui_base_url

  cloudtrail_logs_bucket      = var.cloudtrail_logs_bucket
  cloudtrail_logs_prefix      = var.cloudtrail_logs_prefix
  cloudtrail_organization_id  = var.cloudtrail_organization_id
  cloudtrail_logs_kms_key_arn = var.cloudtrail_logs_kms_key_arn
  analysis_days               = var.analysis_days
  securityhub_reader_role_arn = var.securityhub_reader_role_arn

  dspm_bucket_allowlist     = var.dspm_bucket_allowlist
  macie_enabled             = var.macie_enabled
  allow_public_https_egress = var.allow_public_https_egress

  tags = var.tags
}

# IRSA role for the External Secrets controller's ServiceAccount. External
# Secrets reads the runtime secret (COLLECTOR_EXTERNAL_ID, GRAPH_WRITER_TOKEN)
# and decrypts it with the data-plane CMK; no workload reads it directly.
locals {
  oidc_issuer = trimprefix(
    var.oidc_provider_arn,
    "arn:${split(":", var.oidc_provider_arn)[1]}:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/"
  )
  external_secrets_service_account = "${var.release_name}-external-secrets"
}

resource "aws_iam_role" "external_secrets" {
  name = "${var.name_prefix}-khalifa-external-secrets"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = var.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_issuer}:aud" = "sts.amazonaws.com"
          "${local.oidc_issuer}:sub" = "system:serviceaccount:${var.namespace}:${local.external_secrets_service_account}"
        }
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "external_secrets_runtime_secret" {
  name = "read-runtime-secret"
  role = aws_iam_role.external_secrets.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
        ]
        Resource = [module.khalifa_data.runtime_secret_arn]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
        ]
        Resource = [module.khalifa_data.kms_key_arn]
      },
    ]
  })
}

module "khalifa_eks" {
  source = "../../khalifa-eks"
  count  = var.install_chart ? 1 : 0

  providers = {
    helm = helm
  }

  namespace    = var.namespace
  release_name = var.release_name
  values       = local.chart_values

  depends_on = [aws_iam_role_policy.external_secrets_runtime_secret]
}
