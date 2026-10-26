locals {
  dynamodb_table_arns = [
    aws_dynamodb_table.issues.arn,
    aws_dynamodb_table.evidence.arn,
    aws_dynamodb_table.reports.arn,
    aws_dynamodb_table.posture_trends.arn,
    aws_dynamodb_table.access_analyzer.arn,
    aws_dynamodb_table.least_privilege.arn,
  ]
  dynamodb_index_arns = [for arn in local.dynamodb_table_arns : "${arn}/index/*"]

  # The API reads compliance evidence and reports (Query only); the rule-runner
  # writes them. Splitting the statements lets the API drop DeleteItem/Scan on
  # those two tables while the rule-runner keeps full access.
  compliance_table_arns = [
    aws_dynamodb_table.evidence.arn,
    aws_dynamodb_table.reports.arn,
  ]
  core_table_arns = [
    aws_dynamodb_table.issues.arn,
    aws_dynamodb_table.posture_trends.arn,
    aws_dynamodb_table.access_analyzer.arn,
    aws_dynamodb_table.least_privilege.arn,
  ]
  dynamodb_full_actions = [
    "dynamodb:BatchGetItem",
    "dynamodb:BatchWriteItem",
    "dynamodb:DeleteItem",
    "dynamodb:DescribeTable",
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:Query",
    "dynamodb:Scan",
    "dynamodb:UpdateItem",
  ]
  dynamodb_read_actions = [
    "dynamodb:BatchGetItem",
    "dynamodb:DescribeTable",
    "dynamodb:GetItem",
    "dynamodb:Query",
  ]

  # Workloads only ever touch the CMK through a data-plane service, so bind the
  # grant to those services. Any direct kms:* call is denied.
  kms_via_services = [
    "athena.${data.aws_region.current.region}.amazonaws.com",
    "dynamodb.${data.aws_region.current.region}.amazonaws.com",
    "logs.${data.aws_region.current.region}.amazonaws.com",
    "s3.${data.aws_region.current.region}.amazonaws.com",
    "secretsmanager.${data.aws_region.current.region}.amazonaws.com",
    "sns.${data.aws_region.current.region}.amazonaws.com",
    "sqs.${data.aws_region.current.region}.amazonaws.com",
  ]

  neptune_resource_arn = format(
    "arn:aws:neptune-db:%s:%s:%s/*",
    data.aws_region.current.region,
    data.aws_caller_identity.current.account_id,
    aws_neptune_cluster.this.cluster_resource_id
  )

  # Same actions as templates/SecurityGraphCollectorRole.yaml. Home collection
  # uses ambient IRSA (no self-assume), so the hub roles need these reads.
  home_collection_statements = [
    {
      Sid    = "ComputeNetworkRead"
      Effect = "Allow"
      Action = [
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcs",
        "ec2:GetEbsEncryptionByDefault",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "eks:DescribeCluster",
        "eks:ListClusters",
        "elasticloadbalancing:DescribeLoadBalancers",
        "tag:GetResources",
      ]
      Resource = ["*"]
    },
    {
      Sid    = "IdentityRead"
      Effect = "Allow"
      Action = [
        "access-analyzer:ListAnalyzers",
        "access-analyzer:ListFindings",
        "iam:GenerateCredentialReport",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetCredentialReport",
        "iam:GetGroupPolicy",
        "iam:GetLoginProfile",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:GetUser",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupPolicies",
        "iam:ListGroupsForUser",
        "iam:ListGroups",
        "iam:ListInstanceProfiles",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:ListPolicyVersions",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListServerCertificates",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "iam:ListVirtualMFADevices",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListKeys",
      ]
      Resource = ["*"]
    },
    {
      Sid    = "DataRead"
      Effect = "Allow"
      Action = [
        "backup:ListBackupPlans",
        "backup:ListBackupVaults",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "elasticache:DescribeCacheClusters",
        "elasticfilesystem:DescribeFileSystems",
        "es:DescribeDomain",
        "es:ListDomainNames",
        "rds:DescribeDBInstances",
        "redshift:DescribeClusters",
        "s3:GetBucketPolicy",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:ListAllMyBuckets",
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetResourcePolicy",
        "secretsmanager:ListSecrets",
        "ssm:DescribeParameters",
      ]
      Resource = ["*"]
    },
    {
      Sid    = "PlatformRead"
      Effect = "Allow"
      Action = [
        "apigateway:GET",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudwatch:DescribeAlarms",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigRules",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetInsightSelectors",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels",
        "config:DescribeDeliveryChannelStatus",
        "events:ListEventBuses",
        "guardduty:GetAdministratorAccount",
        "guardduty:GetDetector",
        "guardduty:ListDetectors",
        "guardduty:ListMembers",
        "guardduty:ListPublishingDestinations",
        "inspector2:ListFindings",
        "lambda:GetPolicy",
        "lambda:ListAliases",
        "lambda:ListFunctions",
        "lambda:ListFunctionUrlConfigs",
        "logs:DescribeLogGroups",
        "logs:DescribeMetricFilters",
        "route53:ListHostedZones",
        "securityhub:DescribeHub",
        "securityhub:DescribeStandards",
        "securityhub:GetEnabledStandards",
        "securityhub:GetFindings",
        "securityhub:ListEnabledProductsForImport",
        "states:ListStateMachines",
      ]
      Resource = ["*"]
    },
    {
      # Observed reachability: the collector reads the flow-log analyzer's
      # per-interface observations while it collects instances. The read runs
      # with the hub's own credentials, so only the hub roles need it.
      Sid      = "TrafficObservationsRead"
      Effect   = "Allow"
      Action   = ["dynamodb:BatchGetItem", "dynamodb:DescribeTable", "dynamodb:GetItem"]
      Resource = [aws_dynamodb_table.traffic_observations.arn]
    },
  ]
}

resource "aws_iam_role" "workloads" {
  for_each = local.service_accounts

  name = "${local.name}-${each.key}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "EksIrsa"
      Effect = "Allow"
      Principal = {
        Federated = var.oidc_provider_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_issuer}:aud" = "sts.amazonaws.com"
          "${local.oidc_issuer}:sub" = "system:serviceaccount:${var.namespace}:${each.value}"
        }
      }
    }]
  })

  tags = merge(var.tags, { Name = "${local.name}-${each.key}" })
}

resource "aws_iam_role_policy" "api" {
  name = "${local.name}-api"
  role = aws_iam_role.workloads["api"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDb"
        Effect   = "Allow"
        Action   = local.dynamodb_full_actions
        Resource = concat(local.core_table_arns, [for arn in local.core_table_arns : "${arn}/index/*"])
      },
      {
        # Evidence and reports are read-only for the API; only the rule-runner
        # writes them. No DeleteItem, no Scan.
        Sid      = "ComplianceRead"
        Effect   = "Allow"
        Action   = local.dynamodb_read_actions
        Resource = concat(local.compliance_table_arns, [for arn in local.compliance_table_arns : "${arn}/index/*"])
      },
      {
        Sid      = "ThreatIndicators"
        Effect   = "Allow"
        Action   = local.dynamodb_full_actions
        Resource = [aws_dynamodb_table.threat_indicators.arn]
      },
      {
        Sid      = "IssuesTopic"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.issues.arn]
      },
      {
        Sid    = "NeptuneRead"
        Effect = "Allow"
        Action = [
          "neptune-db:ReadDataViaQuery",
          "neptune-db:GetEngineStatus",
        ]
        Resource = [local.neptune_resource_arn]
      },
    ]
  })
}

resource "aws_iam_role_policy" "rule_runner" {
  name = "${local.name}-rule-runner"
  role = aws_iam_role.workloads["rule-runner"].id
  policy = jsonencode({
    Version = "2012-10-17"
    # The rule-runner writes evidence, reports, issues, and posture trends and
    # scans issues/evidence, so it keeps full table access. It no longer shares
    # the API policy, whose compliance reads the API tightening made read-only.
    Statement = [
      {
        Sid      = "DynamoDb"
        Effect   = "Allow"
        Action   = local.dynamodb_full_actions
        Resource = concat(local.dynamodb_table_arns, local.dynamodb_index_arns)
      },
      {
        Sid      = "IssuesTopic"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.issues.arn]
      },
      {
        Sid    = "NeptuneRead"
        Effect = "Allow"
        Action = [
          "neptune-db:ReadDataViaQuery",
          "neptune-db:GetEngineStatus",
        ]
        Resource = [local.neptune_resource_arn]
      },
      {
        Sid      = "ThreatIntelLists"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = var.threat_intel_list_bucket != "" ? ["arn:aws:s3:::${var.threat_intel_list_bucket}/*"] : []
      },
    ]
  })
}

resource "aws_iam_role_policy" "graph_writer" {
  name = "${local.name}-graph-writer"
  role = aws_iam_role.workloads["graph-writer"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "NeptuneWrite"
        Effect = "Allow"
        Action = [
          "neptune-db:ReadDataViaQuery",
          "neptune-db:WriteDataViaQuery",
          "neptune-db:DeleteDataViaQuery",
          "neptune-db:GetEngineStatus",
        ]
        Resource = [local.neptune_resource_arn]
      },
    ]
  })
}

resource "aws_iam_role_policy" "compliance" {
  name = "${local.name}-compliance"
  role = aws_iam_role.workloads["compliance"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "ComplianceTables"
        Effect = "Allow"
        Action = [
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:DeleteItem",
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem",
        ]
        Resource = [
          aws_dynamodb_table.evidence.arn,
          "${aws_dynamodb_table.evidence.arn}/index/*",
          aws_dynamodb_table.reports.arn,
          "${aws_dynamodb_table.reports.arn}/index/*",
        ]
      },
      {
        # Rule-backed controls read their rules' open issues (RuleIdIndex).
        # Read-only: compliance never writes issues.
        Sid    = "IssuesRead"
        Effect = "Allow"
        Action = [
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:Query",
        ]
        Resource = [
          aws_dynamodb_table.issues.arn,
          "${aws_dynamodb_table.issues.arn}/index/*",
        ]
      },
      {
        Sid    = "NeptuneRead"
        Effect = "Allow"
        Action = [
          "neptune-db:ReadDataViaQuery",
          "neptune-db:GetEngineStatus",
        ]
        Resource = [local.neptune_resource_arn]
      },
      ],
      # CIS reconciliation (SEC-3254): read Security Hub through the audit
      # account's read-only khalifa-securityhub-reader role. Off when unset.
      var.securityhub_reader_role_arn == "" ? [] : [
        {
          Sid      = "AssumeSecurityHubReader"
          Effect   = "Allow"
          Action   = "sts:AssumeRole"
          Resource = var.securityhub_reader_role_arn
        },
    ])
  })
}

resource "aws_iam_role_policy" "organization_collector" {
  name = "${local.name}-organization-collector"
  role = aws_iam_role.workloads["organization-collector"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AssumeMemberCollector"
          Effect = "Allow"
          Action = ["sts:AssumeRole"]
          # Only the approved accounts can be assumed. With no approved ids the
          # module relies on organization discovery, so no account can be named;
          # the ExternalId condition below still applies. Set
          # collection_account_ids to tighten this to an explicit allowlist.
          Resource = length(var.collection_account_ids) > 0 ? [
            for account_id in var.collection_account_ids :
            "arn:aws:iam::${account_id}:role/${var.collector_role_name}"
          ] : ["arn:aws:iam::*:role/${var.collector_role_name}"]
          # Must match COLLECTOR_EXTERNAL_ID sent by the collector and the
          # member role's trust policy.
          Condition = {
            StringEquals = {
              # Not a credential: an external ID is a confused-deputy guard, and
              # the collector receives it as plain configuration. Marking it
              # non-sensitive keeps the policy readable in plans and tests.
              "sts:ExternalId" = nonsensitive(random_password.collector_external_id.result)
            }
          }
        },
        {
          Sid    = "OrganizationsRead"
          Effect = "Allow"
          Action = [
            "organizations:ListAccounts",
            "organizations:ListAccountsForParent",
            "organizations:ListOrganizationalUnitsForParent",
          ]
          Resource = ["*"]
        },
      ],
      local.home_collection_statements
    )
  })
}

resource "aws_iam_role_policy" "cloudtrail_analyzer" {
  name = "${local.name}-cloudtrail-analyzer"
  role = aws_iam_role.workloads["cloudtrail-analyzer"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AccessAnalyzerCache"
          Effect = "Allow"
          Action = [
            "dynamodb:BatchGetItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:DescribeTable",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:UpdateItem",
          ]
          Resource = [
            aws_dynamodb_table.access_analyzer.arn,
            "${aws_dynamodb_table.access_analyzer.arn}/index/*",
          ]
        },
      ],
      local.cloudtrail_enabled ? [
        {
          Sid    = "AthenaWorkgroup"
          Effect = "Allow"
          Action = [
            "athena:GetQueryExecution",
            "athena:GetQueryResults",
            "athena:StartQueryExecution",
            "athena:StopQueryExecution",
          ]
          Resource = [aws_athena_workgroup.cloudtrail[0].arn]
        },
        {
          Sid    = "GlueCatalog"
          Effect = "Allow"
          Action = [
            "glue:GetDatabase",
            "glue:GetTable",
            "glue:GetPartition",
            "glue:GetPartitions",
          ]
          Resource = [
            "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:catalog",
            aws_glue_catalog_database.cloudtrail[0].arn,
            aws_glue_catalog_table.cloudtrail_logs[0].arn,
          ]
        },
        {
          Sid    = "AthenaResults"
          Effect = "Allow"
          Action = [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:PutObject",
          ]
          Resource = [
            aws_s3_bucket.athena_results[0].arn,
            "${aws_s3_bucket.athena_results[0].arn}/*",
          ]
        },
        {
          Sid      = "CloudTrailLogs"
          Effect   = "Allow"
          Action   = ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"]
          Resource = ["arn:aws:s3:::${var.cloudtrail_logs_bucket}", "arn:aws:s3:::${var.cloudtrail_logs_bucket}/*"]
        },
      ] : [],
      local.cloudtrail_enabled && var.cloudtrail_logs_kms_key_arn != "" ? [
        {
          Sid      = "CloudTrailLogsKey"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.cloudtrail_logs_kms_key_arn]
        },
      ] : [],
      local.flow_logs_enabled ? [
        {
          Sid    = "TrafficObservations"
          Effect = "Allow"
          Action = [
            "dynamodb:BatchWriteItem",
            "dynamodb:DescribeTable",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
          ]
          Resource = [aws_dynamodb_table.traffic_observations.arn]
        },
        {
          Sid    = "FlowLogsGlueTable"
          Effect = "Allow"
          Action = [
            "glue:GetPartition",
            "glue:GetPartitions",
            "glue:GetTable",
          ]
          Resource = [
            "arn:aws:glue:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:catalog",
            aws_glue_catalog_database.cloudtrail[0].arn,
            aws_glue_catalog_table.vpc_flow_logs[0].arn,
          ]
        },
        {
          Sid      = "FlowLogsBucket"
          Effect   = "Allow"
          Action   = ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"]
          Resource = ["arn:aws:s3:::${var.flow_logs_bucket}", "arn:aws:s3:::${var.flow_logs_bucket}/*"]
        },
      ] : [],
      local.flow_logs_enabled && var.flow_logs_kms_key_arn != "" ? [
        {
          Sid      = "FlowLogsKey"
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.flow_logs_kms_key_arn]
        },
      ] : []
    )
  })
}

resource "aws_iam_role_policy" "dspm_scanner" {
  name = "${local.name}-dspm-scanner"
  role = aws_iam_role.workloads["dspm-scanner"].id
  policy = jsonencode({
    Version = "2012-10-17"
    # Content reads require an explicit allowlist. An empty list grants no
    # object access at all: falling back to every bucket is the broad grant
    # this workstream exists to remove. Bucket tags cannot scope this either:
    # S3 objects are not matched by aws:ResourceTag, and the opt-in dspm-scan
    # tag lives on the bucket.
    Statement = concat(
      length(var.dspm_bucket_allowlist) > 0 ? [
        {
          Sid    = "S3ReadForSecretScan"
          Effect = "Allow"
          Action = ["s3:ListBucket", "s3:GetObject", "s3:GetBucketTagging"]
          Resource = concat(
            [for bucket in var.dspm_bucket_allowlist : "arn:aws:s3:::${bucket}"],
            [for bucket in var.dspm_bucket_allowlist : "arn:aws:s3:::${bucket}/*"]
          )
        },
      ] : [],
      [
        {
          # Listing bucket names cannot be resource-scoped.
          Sid      = "S3ListBucketsForSecretScan"
          Effect   = "Allow"
          Action   = ["s3:ListAllMyBuckets"]
          Resource = ["*"]
        },
        {
          Sid      = "LambdaEnvForSecretScan"
          Effect   = "Allow"
          Action   = ["lambda:ListFunctions"]
          Resource = ["*"]
        },
        {
          Sid      = "MacieReadForSecretScan"
          Effect   = "Allow"
          Action   = ["macie2:ListFindings", "macie2:GetFindings", "macie2:DescribeBuckets"]
          Resource = ["*"]
        },
        {
          # The bucket inventory comes from the graph (all collected accounts),
          # not S3 ListBuckets, so the scanner needs graph read.
          Sid    = "NeptuneRead"
          Effect = "Allow"
          Action = [
            "neptune-db:ReadDataViaQuery",
            "neptune-db:GetEngineStatus",
          ]
          Resource = [local.neptune_resource_arn]
        },
      ]
    )
  })
}

resource "aws_iam_role_policy" "incremental_collector" {
  name = "${local.name}-incremental-collector"
  role = aws_iam_role.workloads["incremental-collector"].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Sid    = "AssumeMemberCollector"
          Effect = "Allow"
          Action = ["sts:AssumeRole"]
          # Only the approved accounts can be assumed. With no approved ids the
          # module relies on organization discovery, so no account can be named;
          # the ExternalId condition below still applies. Set
          # collection_account_ids to tighten this to an explicit allowlist.
          Resource = length(var.collection_account_ids) > 0 ? [
            for account_id in var.collection_account_ids :
            "arn:aws:iam::${account_id}:role/${var.collector_role_name}"
          ] : ["arn:aws:iam::*:role/${var.collector_role_name}"]
          # Must match COLLECTOR_EXTERNAL_ID sent by the collector and the
          # member role's trust policy.
          Condition = {
            StringEquals = {
              # Not a credential: an external ID is a confused-deputy guard, and
              # the collector receives it as plain configuration. Marking it
              # non-sensitive keeps the policy readable in plans and tests.
              "sts:ExternalId" = nonsensitive(random_password.collector_external_id.result)
            }
          }
        },
        {
          Sid    = "OrganizationsRead"
          Effect = "Allow"
          Action = [
            "organizations:ListAccounts",
            "organizations:ListAccountsForParent",
            "organizations:ListOrganizationalUnitsForParent",
          ]
          Resource = ["*"]
        },
        {
          Sid    = "IncrementalQueue"
          Effect = "Allow"
          Action = [
            "sqs:ChangeMessageVisibility",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl",
            "sqs:ReceiveMessage",
          ]
          Resource = [aws_sqs_queue.incremental.arn]
        },
      ],
      local.home_collection_statements
    )
  })
}

resource "aws_iam_role_policy" "policy_evaluator" {
  name = "${local.name}-policy-evaluator"
  role = aws_iam_role.workloads["policy-evaluator"].id
  policy = jsonencode({
    Version = "2012-10-17"
    # SigV4, like graph-writer: the evaluator upserts EffectivePermission and
    # EscalationPath vertices straight to Neptune and touches no DynamoDB table.
    # `DeleteDataViaQuery` is required on the *second* run: replacing a
    # single-cardinality property value is authorized as a delete (graph-writer
    # carries it for the same reason). Without it the first run adds, and every
    # re-run fails with AccessDeniedException.
    Statement = [
      {
        Sid    = "NeptuneReadWrite"
        Effect = "Allow"
        Action = [
          "neptune-db:ReadDataViaQuery",
          "neptune-db:WriteDataViaQuery",
          "neptune-db:DeleteDataViaQuery",
          "neptune-db:GetEngineStatus",
        ]
        Resource = [local.neptune_resource_arn]
      },
    ]
  })
}

resource "aws_iam_role_policy" "least_privilege_sweep" {
  name = "${local.name}-least-privilege-sweep"
  role = aws_iam_role.workloads["least-privilege-sweep"].id
  policy = jsonencode({
    Version = "2012-10-17"
    # Reads the graph to reproduce the effective permissions, reads the
    # analyzer's usage cache, and writes one finding per principal.
    Statement = [
      {
        Sid    = "NeptuneRead"
        Effect = "Allow"
        Action = [
          "neptune-db:ReadDataViaQuery",
          "neptune-db:GetEngineStatus",
        ]
        Resource = [local.neptune_resource_arn]
      },
      {
        Sid      = "AccessAnalyzerCacheRead"
        Effect   = "Allow"
        Action   = ["dynamodb:Query"]
        Resource = [aws_dynamodb_table.access_analyzer.arn]
      },
      {
        Sid      = "LeastPrivilegeFindingsWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [aws_dynamodb_table.least_privilege.arn]
      },
    ]
  })
}

resource "aws_iam_role_policy" "kms" {
  for_each = aws_iam_role.workloads
  name     = "${local.name}-${each.key}-kms"
  role     = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "KhalifaCmk"
      Effect = "Allow"
      Action = [
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:GenerateDataKey",
      ]
      Resource = [aws_kms_key.this.arn]
      # Workloads only use the CMK through a data-plane service; a direct
      # kms:* call is out of scope and denied.
      Condition = {
        StringEquals = {
          "kms:ViaService" = local.kms_via_services
        }
      }
    }]
  })
}
