mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-west-2"
    }
  }

  mock_resource "aws_neptune_cluster" {
    defaults = {
      endpoint            = "example-khalifa.cluster-example.us-west-2.neptune.amazonaws.com"
      cluster_resource_id = "cluster-ABCDEF"
    }
  }

  mock_resource "aws_cognito_user_pool" {
    defaults = {
      id = "us-west-2_example"
    }
  }

  mock_resource "aws_cognito_user_pool_client" {
    defaults = {
      id = "exampleclientid"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      url = "https://sqs.us-west-2.amazonaws.com/111122223333/example-khalifa-incremental.fifo"
      arn = "arn:aws:sqs:us-west-2:111122223333:example-khalifa-incremental.fifo"
    }
  }

  mock_resource "aws_dynamodb_table" {
    defaults = {
      arn = "arn:aws:dynamodb:us-west-2:111122223333:table/example-khalifa-issues"
    }
  }

  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111122223333:example-khalifa-issues"
    }
  }

  mock_resource "aws_secretsmanager_secret" {
    defaults = {
      arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:example-khalifa/runtime"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111122223333:role/example-khalifa-api"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000"
    }
  }

  mock_data "aws_regions" {
    defaults = {
      names = ["us-east-1", "us-west-2"]
    }
  }

  mock_data "aws_subnet" {
    defaults = {
      availability_zone = "us-west-2a"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::example-khalifa-athena-results"
    }
  }

  mock_resource "aws_athena_workgroup" {
    defaults = {
      arn = "arn:aws:athena:us-west-2:111122223333:workgroup/example-khalifa-cloudtrail"
    }
  }

  mock_resource "aws_glue_catalog_database" {
    defaults = {
      arn = "arn:aws:glue:us-west-2:111122223333:database/security_prod_khalifa_cloudtrail"
    }
  }

  mock_resource "aws_glue_catalog_table" {
    defaults = {
      arn = "arn:aws:glue:us-west-2:111122223333:table/security_prod_khalifa_cloudtrail/cloudtrail_logs"
    }
  }
}

mock_provider "random" {
  override_during = plan

  # The collector ExternalId feeds the hub's sts:AssumeRole condition, so the
  # policy JSON must be known during plan for the assertions below to evaluate.
  mock_resource "random_password" {
    defaults = {
      result = "test-external-id-0123456789"
    }
  }
}

run "data_plane" {
  command = plan

  variables {
    # Approved accounts: exercises the tightened AssumeMemberCollector resource.
    collection_account_ids = ["444455556666"]
    dspm_bucket_allowlist  = ["approved-dspm-bucket"]
    name_prefix            = "example"
    vpc_id                 = "vpc-0123456789abcdef0"
    vpc_cidr               = "10.2.0.0/16"
    private_subnet_ids     = ["subnet-aaa", "subnet-bbb"]
    node_security_group_id = "sg-nodes"
    oidc_provider_arn      = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
    home_account_id        = "111122223333"
    ui_base_url            = "https://khalifa.example.com"
  }

  assert {
    condition     = aws_dynamodb_table.issues.name == "example-khalifa-issues"
    error_message = "Issues table must use the environment prefix."
  }

  assert {
    condition     = aws_sqs_queue.incremental.fifo_queue && aws_sqs_queue.incremental_dlq.fifo_queue
    error_message = "Incremental collection must use a FIFO queue and DLQ."
  }

  assert {
    condition     = aws_neptune_cluster.this.iam_database_authentication_enabled && aws_neptune_cluster.this.storage_encrypted && aws_neptune_cluster.this.deletion_protection
    error_message = "Neptune must use IAM auth, encryption, and deletion protection."
  }

  assert {
    condition     = aws_cognito_user_pool.this.mfa_configuration == "ON"
    error_message = "The Cognito user pool must require MFA."
  }

  assert {
    condition = toset([for group in aws_cognito_user_group.roles : group.name]) == toset([
      "khalifa-admin",
      "khalifa-analyst",
      "khalifa-viewer",
    ])
    error_message = "Cognito must create the three Khalifa RBAC groups."
  }

  assert {
    condition = jsondecode(aws_iam_role.workloads["graph-writer"].assume_role_policy).Statement[0].Condition.StringEquals == {
      "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud" = "sts.amazonaws.com"
      "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub" = "system:serviceaccount:khalifa:khalifa-graph-writer"
    }
    error_message = "Graph-writer IRSA trust must bind the Helm ServiceAccount."
  }

  assert {
    condition = (
      contains(
        jsondecode(aws_iam_role_policy.organization_collector.policy).Statement[0].Resource,
        "arn:aws:iam::444455556666:role/SecurityGraphCollectorRole"
      ) &&
      jsondecode(aws_iam_role_policy.organization_collector.policy).Statement[0].Condition.StringEquals["sts:ExternalId"] == "test-external-id-0123456789"
    )
    error_message = "Collectors must assume the member collector role only in approved accounts and present an external ID."
  }

  assert {
    condition = !contains(
      jsondecode(aws_iam_role_policy.organization_collector.policy).Statement[0].Resource,
      "arn:aws:iam::*:role/SecurityGraphCollectorRole"
    )
    error_message = "The hub must not be able to assume the collector role in unapproved accounts."
  }

  assert {
    condition = contains(
      flatten([
        for statement in jsondecode(aws_iam_role_policy.organization_collector.policy).Statement :
        statement.Action if statement.Sid == "ComputeNetworkRead"
      ]),
      "ec2:DescribeInstances"
    )
    error_message = "Home collection uses ambient IRSA and needs the spoke collection reads."
  }

  assert {
    condition = contains(
      jsondecode(aws_iam_role_policy.cloudtrail_analyzer.policy).Statement[0].Resource,
      aws_dynamodb_table.access_analyzer.arn
    )
    error_message = "CloudTrail analyzer IRSA must write AccessAnalyzerCache."
  }

  assert {
    condition     = contains(keys(aws_iam_role.workloads), "cloudtrail-analyzer")
    error_message = "Data plane must create the cloudtrail-analyzer IRSA role."
  }

  assert {
    condition = alltrue([
      contains(keys(aws_iam_role.workloads), "policy-evaluator"),
      contains(keys(aws_iam_role.workloads), "least-privilege-sweep"),
    ])
    error_message = "Data plane must create IRSA roles for both CIEM workloads."
  }

  assert {
    condition = (
      jsondecode(aws_iam_role.workloads["policy-evaluator"].assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub"] == "system:serviceaccount:khalifa:khalifa-policy-evaluator" &&
      jsondecode(aws_iam_role.workloads["least-privilege-sweep"].assume_role_policy).Statement[0].Condition.StringEquals["oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub"] == "system:serviceaccount:khalifa:khalifa-least-privilege-sweep"
    )
    error_message = "CIEM IRSA trust must bind the Helm ServiceAccount names."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.policy_evaluator.policy).Statement :
      flatten([statement.Action])
      ])) == toset([
      "neptune-db:ReadDataViaQuery",
      "neptune-db:WriteDataViaQuery",
      "neptune-db:DeleteDataViaQuery",
      "neptune-db:GetEngineStatus",
    ])
    error_message = "The policy evaluator policy must contain exactly the Neptune read/write/delete actions and nothing else."
  }

  assert {
    condition = (
      toset(flatten([
        for statement in jsondecode(aws_iam_role_policy.least_privilege_sweep.policy).Statement :
        flatten([statement.Action])
        ])) == toset([
        "neptune-db:ReadDataViaQuery",
        "neptune-db:GetEngineStatus",
        "dynamodb:Query",
        "dynamodb:PutItem",
      ]) &&
      toset(flatten([
        for statement in jsondecode(aws_iam_role_policy.least_privilege_sweep.policy).Statement :
        flatten([statement.Resource]) if statement.Sid == "AccessAnalyzerCacheRead"
      ])) == toset([aws_dynamodb_table.access_analyzer.arn]) &&
      toset(flatten([
        for statement in jsondecode(aws_iam_role_policy.least_privilege_sweep.policy).Statement :
        flatten([statement.Resource]) if statement.Sid == "LeastPrivilegeFindingsWrite"
      ])) == toset([aws_dynamodb_table.least_privilege.arn])
    )
    error_message = "The sweep policy must contain exactly the Neptune read, analyzer-query, and findings-write actions on exactly their tables."
  }

  assert {
    condition = alltrue([
      for policy in [
        aws_iam_role_policy.api,
        aws_iam_role_policy.graph_writer,
        aws_iam_role_policy.compliance,
        aws_iam_role_policy.policy_evaluator,
        aws_iam_role_policy.least_privilege_sweep,
      ] :
      !anytrue([
        for statement in jsondecode(policy.policy).Statement :
        contains(flatten([statement.Action]), "secretsmanager:GetSecretValue")
      ])
    ])
    error_message = "Neptune access is SigV4; no workload policy may read the Neptune secret."
  }

  assert {
    condition = (
      output.helm_values.config.athenaDatabase == "" &&
      length(aws_athena_workgroup.cloudtrail) == 0 &&
      length([for statement in jsondecode(aws_iam_role_policy.cloudtrail_analyzer.policy).Statement : statement if statement.Sid == "CloudTrailLogs"]) == 0
    )
    error_message = "Without a trail bucket the analyzer gets no Athena resources or trail permissions."
  }

  assert {
    condition     = !contains(keys(output.helm_values.config), "externalId") && !contains(keys(output.helm_values.config), "token")
    error_message = "helm_values must not include collector or graph-writer secrets."
  }

  assert {
    condition     = aws_kms_alias.this.name == "alias/example-khalifa" && aws_kms_key.this.enable_key_rotation
    error_message = "Data-plane CMK must exist with rotation and the environment alias."
  }

  assert {
    condition = alltrue([
      aws_dynamodb_table.issues.server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn,
      aws_dynamodb_table.evidence.server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn,
      aws_dynamodb_table.reports.server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn,
      aws_dynamodb_table.posture_trends.server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn,
      aws_dynamodb_table.access_analyzer.server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn,
      aws_dynamodb_table.least_privilege.server_side_encryption[0].kms_key_arn == aws_kms_key.this.arn,
    ])
    error_message = "All DynamoDB tables must use the Khalifa CMK."
  }

  assert {
    condition = alltrue([
      aws_dynamodb_table.issues.deletion_protection_enabled,
      aws_dynamodb_table.evidence.deletion_protection_enabled,
      aws_dynamodb_table.reports.deletion_protection_enabled,
      aws_dynamodb_table.posture_trends.deletion_protection_enabled,
      aws_dynamodb_table.access_analyzer.deletion_protection_enabled,
      aws_dynamodb_table.least_privilege.deletion_protection_enabled,
      aws_dynamodb_table.issues.point_in_time_recovery[0].enabled,
      aws_dynamodb_table.evidence.point_in_time_recovery[0].enabled,
      aws_dynamodb_table.reports.point_in_time_recovery[0].enabled,
      aws_dynamodb_table.posture_trends.point_in_time_recovery[0].enabled,
      aws_dynamodb_table.access_analyzer.point_in_time_recovery[0].enabled,
      aws_dynamodb_table.least_privilege.point_in_time_recovery[0].enabled,
    ])
    error_message = "Every DynamoDB table must have deletion protection and point-in-time recovery."
  }

  assert {
    condition = alltrue([
      aws_sqs_queue.incremental.kms_master_key_id == aws_kms_key.this.arn,
      aws_sqs_queue.incremental_dlq.kms_master_key_id == aws_kms_key.this.arn,
      aws_sns_topic.issues.kms_master_key_id == aws_kms_key.this.arn,
    ])
    error_message = "SQS queues and the issues SNS topic must use the Khalifa CMK."
  }

  assert {
    condition = (
      contains(
        jsondecode(aws_iam_role_policy.dspm_scanner.policy).Statement[0].Resource,
        "arn:aws:s3:::approved-dspm-bucket/*"
      ) &&
      !contains(
        jsondecode(aws_iam_role_policy.dspm_scanner.policy).Statement[0].Resource,
        "arn:aws:s3:::*/*"
      ) &&
      jsondecode(aws_iam_role_policy.dspm_scanner.policy).Statement[1].Action == ["s3:ListAllMyBuckets"]
    )
    error_message = "The DSPM scanner must read objects only from the approved buckets."
  }

  assert {
    condition = alltrue([
      aws_secretsmanager_secret.runtime.kms_key_id == aws_kms_key.this.arn,
      aws_secretsmanager_secret.neptune.kms_key_id == aws_kms_key.this.arn,
      aws_neptune_cluster.this.kms_key_arn == aws_kms_key.this.arn,
      aws_cloudwatch_log_group.neptune_audit.kms_key_id == aws_kms_key.this.arn,
    ])
    error_message = "Secrets, Neptune storage, and Neptune audit logs must use the Khalifa CMK."
  }

  assert {
    condition = alltrue([
      for key in keys(aws_iam_role.workloads) :
      contains(jsondecode(aws_iam_role_policy.kms[key].policy).Statement[0].Resource, aws_kms_key.this.arn)
    ])
    error_message = "Every workload IRSA role must be allowed to use the Khalifa CMK."
  }

  assert {
    condition = alltrue([
      for key in keys(aws_iam_role.workloads) :
      contains(
        jsondecode(aws_iam_role_policy.kms[key].policy).Statement[0].Condition.StringEquals["kms:ViaService"],
        "dynamodb.${data.aws_region.current.region}.amazonaws.com"
      )
    ])
    error_message = "Every workload KMS policy must be bound to the data-plane services via kms:ViaService."
  }

  assert {
    condition = (
      aws_cognito_user_pool.this.user_pool_tier == "PLUS" &&
      aws_cognito_user_pool.this.deletion_protection == "ACTIVE" &&
      aws_cognito_user_pool.this.user_pool_add_ons[0].advanced_security_mode == "ENFORCED"
    )
    error_message = "The Cognito pool must be Plus-tier, deletion-protected, and enforce advanced security."
  }

  assert {
    condition = (
      aws_neptune_cluster_instance.reader.instance_class == "db.serverless" &&
      aws_neptune_cluster_instance.reader.promotion_tier == 1
    )
    error_message = "Neptune must add a serverless reader in a second AZ for Multi-AZ."
  }

  assert {
    condition = (
      length([for s in jsondecode(aws_iam_role_policy.api.policy).Statement : s if s.Sid == "DynamoDb"]) == 1 &&
      length([for s in jsondecode(aws_iam_role_policy.api.policy).Statement : s if s.Sid == "ComplianceRead"]) == 1 &&
      !contains(flatten([for s in jsondecode(aws_iam_role_policy.api.policy).Statement : s.Action if s.Sid == "ComplianceRead"]), "dynamodb:Scan") &&
      !contains(flatten([for s in jsondecode(aws_iam_role_policy.api.policy).Statement : s.Action if s.Sid == "ComplianceRead"]), "dynamodb:DeleteItem") &&
      contains(flatten([for s in jsondecode(aws_iam_role_policy.api.policy).Statement : s.Action if s.Sid == "ComplianceRead"]), "dynamodb:Query")
    )
    error_message = "The API's compliance statement must be read-only (Query, no Scan/DeleteItem)."
  }

  assert {
    condition = (
      contains(flatten([for s in jsondecode(aws_iam_role_policy.rule_runner.policy).Statement : s.Action if s.Sid == "DynamoDb"]), "dynamodb:DeleteItem") &&
      contains(flatten([for s in jsondecode(aws_iam_role_policy.rule_runner.policy).Statement : s.Action if s.Sid == "DynamoDb"]), "dynamodb:Scan")
    )
    error_message = "The rule-runner must keep full evidence/report access now that it has its own policy."
  }
}

run "cloudtrail_athena" {
  command = plan

  variables {
    name_prefix                 = "example"
    vpc_id                      = "vpc-0123456789abcdef0"
    vpc_cidr                    = "10.2.0.0/16"
    private_subnet_ids          = ["subnet-aaa", "subnet-bbb"]
    node_security_group_id      = "sg-nodes"
    oidc_provider_arn           = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
    home_account_id             = "111122223333"
    collection_account_ids      = ["444455556666"]
    ui_base_url                 = "https://khalifa.example.com"
    cloudtrail_logs_bucket      = "example-cloudtrail-logs-audit-usw2"
    cloudtrail_organization_id  = "o-xxxxxxxxxx"
    cloudtrail_logs_kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000"
  }

  assert {
    condition = (
      aws_glue_catalog_table.cloudtrail_logs[0].parameters["storage.location.template"] ==
      "s3://example-cloudtrail-logs-audit-usw2/AWSLogs/o-xxxxxxxxxx/$${account_id}/CloudTrail/$${region}/$${log_date}" &&
      aws_glue_catalog_table.cloudtrail_logs[0].parameters["projection.account_id.values"] == "111122223333,444455556666"
    )
    error_message = "The CloudTrail table must project account / Region / day partitions over the organization trail path."
  }

  assert {
    condition = (
      aws_athena_workgroup.cloudtrail[0].configuration[0].enforce_workgroup_configuration &&
      aws_athena_workgroup.cloudtrail[0].configuration[0].result_configuration[0].encryption_configuration[0].encryption_option == "SSE_KMS" &&
      aws_athena_workgroup.cloudtrail[0].configuration[0].result_configuration[0].output_location == "s3://example-khalifa-athena-results/results/"
    )
    error_message = "Athena results must land in the module's encrypted results bucket."
  }

  assert {
    condition = (
      output.helm_values.config.athenaDatabase == "security_prod_khalifa_cloudtrail" &&
      output.helm_values.config.athenaWorkgroup == "example-khalifa-cloudtrail" &&
      output.helm_values.config.athenaResultsLocation == "s3://example-khalifa-athena-results/results/"
    )
    error_message = "helm_values must carry the Athena database, workgroup, and results location the analyzer reads."
  }

  assert {
    condition = (
      contains(
        flatten([for statement in jsondecode(aws_iam_role_policy.cloudtrail_analyzer.policy).Statement : statement.Resource if statement.Sid == "CloudTrailLogs"]),
        "arn:aws:s3:::example-cloudtrail-logs-audit-usw2/*"
      ) &&
      contains(
        flatten([for statement in jsondecode(aws_iam_role_policy.cloudtrail_analyzer.policy).Statement : statement.Resource if statement.Sid == "CloudTrailLogsKey"]),
        "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000"
      )
    )
    error_message = "The analyzer role must be allowed to read the trail objects and decrypt them."
  }

  # This run does not set dspm_bucket_allowlist: with no allowlist the scanner
  # must keep only bucket-level listing and no object read.
  assert {
    condition = !anytrue([
      for statement in jsondecode(aws_iam_role_policy.dspm_scanner.policy).Statement :
      contains(tolist(statement.Action), "s3:GetObject")
    ])
    error_message = "Without an allowlist the DSPM scanner must not be able to read object content."
  }

  assert {
    condition = alltrue(
      [
        for entry in output.helm_values.networkPolicies.egressCidrs :
        alltrue([
          for port in entry.ports : port.port == 8182 || port.port == 443
        ])
      ]
    )
    error_message = "NetworkPolicy egress must allow only Neptune (8182) and AWS API (443) ports."
  }

  assert {
    condition = alltrue(
      [
        for entry in output.helm_values.networkPolicies.egressCidrs :
        alltrue([for port in entry.ports : port.port == 443]) if entry.cidr == "0.0.0.0/0"
      ]
    )
    error_message = "Internet egress must be limited to HTTPS (443)."
  }

}

run "s3_endpoint_policy" {
  command = plan

  variables {
    name_prefix             = "example"
    vpc_id                  = "vpc-0123456789abcdef0"
    vpc_cidr                = "10.2.0.0/16"
    private_subnet_ids      = ["subnet-aaa", "subnet-bbb"]
    node_security_group_id  = "sg-nodes"
    oidc_provider_arn       = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
    home_account_id         = "111122223333"
    ui_base_url             = "https://khalifa.example.com"
    cloudtrail_logs_bucket  = "example-cloudtrail-logs-audit-usw2"
    private_route_table_ids = ["rtb-aaa", "rtb-bbb"]
  }

  assert {
    condition     = aws_vpc_endpoint.s3_gateway[0].vpc_endpoint_type == "Gateway"
    error_message = "The S3 endpoint must be a gateway endpoint attached to the private route tables."
  }

  assert {
    condition = alltrue(
      [
        for statement in jsondecode(aws_vpc_endpoint_policy.s3_gateway[0].policy).Statement :
        alltrue(
          [
            for action in statement.Action :
            action == "s3:ListBucket" ||
            action == "s3:GetObject" ||
            action == "s3:GetBucketLocation" ||
            action == "s3:ListAllMyBuckets" ||
            action == "s3:PutObject" ||
            action == "s3:AbortMultipartUpload"
          ]
        )
      ]
    )
    error_message = "The S3 gateway endpoint policy must stay limited to Khalifa's S3 read and analyzer-results write actions."
  }

  assert {
    condition = contains(
      flatten(
        [
          for statement in jsondecode(aws_vpc_endpoint_policy.s3_gateway[0].policy).Statement :
          statement.Resource if statement.Sid == "S3AnalyzerResultsWriteViaEndpoint"
        ]
      ),
      aws_s3_bucket.athena_results[0].arn
    )
    error_message = "The endpoint policy must allow analyzer result uploads to the results bucket."
  }
}

# CIS reconciliation (SEC-3254): the compliance role may assume the audit
# account's Security Hub reader only when its ARN is set.
run "securityhub_reader_grant_off_by_default" {
  command = plan

  variables {
    name_prefix            = "example"
    vpc_id                 = "vpc-0123456789abcdef0"
    vpc_cidr               = "10.2.0.0/16"
    private_subnet_ids     = ["subnet-aaa", "subnet-bbb"]
    node_security_group_id = "sg-nodes"
    oidc_provider_arn      = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
    home_account_id        = "111122223333"
    ui_base_url            = "https://khalifa.example.com"
  }

  assert {
    condition     = !strcontains(aws_iam_role_policy.compliance.policy, "AssumeSecurityHubReader")
    error_message = "With no securityhub_reader_role_arn, compliance must not get sts:AssumeRole."
  }
}

run "securityhub_reader_grant_when_set" {
  command = plan

  variables {
    name_prefix                 = "example"
    vpc_id                      = "vpc-0123456789abcdef0"
    vpc_cidr                    = "10.2.0.0/16"
    private_subnet_ids          = ["subnet-aaa", "subnet-bbb"]
    node_security_group_id      = "sg-nodes"
    oidc_provider_arn           = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
    home_account_id             = "111122223333"
    ui_base_url                 = "https://khalifa.example.com"
    securityhub_reader_role_arn = "arn:aws:iam::111122223333:role/khalifa-securityhub-reader"
  }

  assert {
    condition = anytrue([
      for statement in jsondecode(aws_iam_role_policy.compliance.policy).Statement :
      statement.Sid == "AssumeSecurityHubReader" && statement.Action == "sts:AssumeRole" && statement.Resource == "arn:aws:iam::111122223333:role/khalifa-securityhub-reader"
    ])
    error_message = "Compliance must be able to assume exactly the configured Security Hub reader role."
  }
}
