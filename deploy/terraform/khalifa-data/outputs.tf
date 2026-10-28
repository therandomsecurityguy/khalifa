output "namespace" {
  description = "Kubernetes namespace expected by the IRSA roles."
  value       = var.namespace
}

output "neptune_endpoint" {
  description = "Gremlin WSS endpoint for Khalifa workloads."
  value       = "wss://${aws_neptune_cluster.this.endpoint}:8182/gremlin"
}

output "neptune_cluster_resource_id" {
  value = aws_neptune_cluster.this.cluster_resource_id
}

output "neptune_security_group_id" {
  value = aws_security_group.neptune.id
}

output "tables" {
  description = "DynamoDB table names keyed by workload use."
  value = {
    issues          = aws_dynamodb_table.issues.name
    evidence        = aws_dynamodb_table.evidence.name
    reports         = aws_dynamodb_table.reports.name
    posture_trends  = aws_dynamodb_table.posture_trends.name
    access_analyzer = aws_dynamodb_table.access_analyzer.name
    least_privilege = aws_dynamodb_table.least_privilege.name
  }
}

output "incremental_queue_url" {
  value = aws_sqs_queue.incremental.url
}

output "incremental_dlq_url" {
  value = aws_sqs_queue.incremental_dlq.url
}

output "issues_topic_arn" {
  value = aws_sns_topic.issues.arn
}

output "kms_key_arn" {
  description = "Customer-managed KMS key used for data-plane encryption at rest."
  value       = aws_kms_key.this.arn
}

output "kms_key_alias" {
  description = "Alias of the Khalifa data-plane CMK."
  value       = aws_kms_alias.this.name
}

output "cognito" {
  value = {
    user_pool_id = aws_cognito_user_pool.this.id
    client_id    = aws_cognito_user_pool_client.this.id
    region       = data.aws_region.current.region
  }
}

output "runtime_secret_arn" {
  description = "Secrets Manager ARN for COLLECTOR_EXTERNAL_ID and GRAPH_WRITER_TOKEN."
  value       = aws_secretsmanager_secret.runtime.arn
}

output "runtime_secret_name" {
  description = "Secrets Manager name of the runtime secret, for External Secrets remoteRef keys."
  value       = aws_secretsmanager_secret.runtime.name
}

output "neptune_secret_arn" {
  value = aws_secretsmanager_secret.neptune.arn
}

output "workload_role_arns" {
  description = "IRSA role ARNs keyed by Helm ServiceAccount suffix."
  value = {
    for key, role in aws_iam_role.workloads : key => role.arn
  }
}

output "service_accounts" {
  value = local.service_accounts
}

output "helm_values" {
  description = "Non-secret chart values derived from this module. Secrets stay in Secrets Manager."
  value = {
    config = {
      awsRegion                   = data.aws_region.current.region
      neptuneEndpoint             = "wss://${aws_neptune_cluster.this.endpoint}:8182/gremlin"
      issuesTable                 = aws_dynamodb_table.issues.name
      evidenceTable               = aws_dynamodb_table.evidence.name
      reportsTable                = aws_dynamodb_table.reports.name
      postureTrendsTable          = aws_dynamodb_table.posture_trends.name
      accessAnalyzerTable         = aws_dynamodb_table.access_analyzer.name
      trafficObservationsTable    = aws_dynamodb_table.traffic_observations.name
      threatIndicatorsTable       = aws_dynamodb_table.threat_indicators.name
      threatIntelCveListS3Uri     = var.threat_intel_cve_list_s3_uri
      threatIntelEpssListS3Uri    = var.threat_intel_epss_list_s3_uri
      threatIntelIpListS3Uri      = var.threat_intel_ip_list_s3_uri
      threatIntelAccountListS3Uri = var.threat_intel_account_list_s3_uri
      threatIntelTtlDays          = var.threat_intel_ttl_days
      leastPrivilegeTable         = aws_dynamodb_table.least_privilege.name
      cognitoUserPoolId           = aws_cognito_user_pool.this.id
      cognitoClientId             = aws_cognito_user_pool_client.this.id
      cognitoRegion               = data.aws_region.current.region
      corsAllowedOrigins          = [var.ui_base_url]
      issueSinks                  = ["sns"]
      issuesTopicArn              = aws_sns_topic.issues.arn
      uiBaseUrl                   = var.ui_base_url
      athenaDatabase              = local.cloudtrail_enabled ? aws_glue_catalog_database.cloudtrail[0].name : ""
      athenaWorkgroup             = local.cloudtrail_enabled ? aws_athena_workgroup.cloudtrail[0].name : ""
      athenaResultsLocation       = local.athena_results_location
      analysisDays                = var.analysis_days
      dspmScanMode                = var.dspm_scan_mode
      macieEnabled                = var.macie_enabled
    }
    collection = {
      homeAccountId       = var.home_account_id
      accountIds          = local.collection_account_ids
      parentIds           = var.collection_parent_ids
      regions             = var.collection_regions
      incrementalQueueUrl = aws_sqs_queue.incremental.url
      recomputeQueueUrl   = aws_sqs_queue.recompute.url
    }
    networkPolicies = {
      enabled = true
      egressCidrs = concat(
        [
          {
            cidr = var.vpc_cidr
            ports = [
              {
                protocol = "TCP"
                port     = 8182
              }
            ]
            components = [
              "api",
              "rule-runner",
              "org-collector",
              "incremental",
              "graph-writer",
              "compliance",
              "cloudtrail-analyzer",
              "policy-evaluator",
              "least-privilege-sweep",
            ]
          },
        ],
        # Workloads reach AWS public API endpoints (DynamoDB, SQS, Secrets
        # Manager, Cognito, S3, SNS, Athena, Glue, Macie, Lambda) on 443. This
        # stays required until interface VPC endpoints exist for those
        # services; once provisioned, disable it and allow the endpoint ENI
        # CIDRs (inside var.vpc_cidr) instead.
        var.allow_public_https_egress ? [
          {
            cidr = "0.0.0.0/0"
            ports = [
              {
                protocol = "TCP"
                port     = 443
              }
            ]
            components = [
              "api",
              "rule-runner",
              "org-collector",
              "incremental",
              "graph-writer",
              "compliance",
              "cloudtrail-analyzer",
              "dspm-scanner",
              "policy-evaluator",
              "least-privilege-sweep",
            ]
          },
        ] : []
      )
    }
  }
}
