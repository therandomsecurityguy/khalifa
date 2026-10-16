# Khalifa data plane

Reusable AWS resources for a Khalifa EKS install:

- DynamoDB tables, incremental FIFO queue + DLQ, and the issues SNS topic
- Private Neptune Serverless cluster with IAM auth, scaling between `neptune_min_capacity` (default 16 NCU) and `neptune_max_capacity` (default 32). Do not lower the floor to save cost: at 2.5 NCU Neptune rejects even single-vertex writes with `MemoryLimitExceededException`, and writes fail for a few minutes during every scale transition.
- Cognito user pool, UI client, and `khalifa-admin` / `khalifa-analyst` / `khalifa-viewer` groups
- Secrets Manager entries for collector ExternalId, graph-writer token, and Neptune auth
- IRSA roles for the Helm ServiceAccounts, including `cloudtrail-analyzer` (AccessAnalyzerCache always; Athena, Glue, and trail-bucket reads only when `cloudtrail_logs_bucket` is set). Organization and incremental collector roles also have the home-account collection reads (same actions as `SecurityGraphCollectorRole`).
- Athena over the organization CloudTrail, when `cloudtrail_logs_bucket` is set: a Glue database `${name_prefix}_khalifa_cloudtrail` with a `cloudtrail_logs` table (partition projection over `account_id` / `region` / `log_date`, accounts = the collection scope), an Athena workgroup that enforces SSE-KMS results in a module-owned bucket with a 7-day expiry, and the matching analyzer IAM. `helm_values.config` then carries `athenaDatabase`, `athenaWorkgroup`, and `athenaResultsLocation`.
- Optional S3 gateway endpoint (`private_route_table_ids`), with an endpoint policy limited to Khalifa's S3 reads plus analyzer result uploads to the module-owned results bucket
- NetworkPolicy egress values: every workload may reach Neptune (8182) inside the VPC; `allow_public_https_egress` (default true) additionally allows TCP 443 to the internet so workloads can reach AWS public API endpoints (DynamoDB, SQS, Secrets Manager, Cognito, S3, Athena, Macie). Once interface VPC endpoints exist for those services, set `allow_public_https_egress = false` to drop the internet rule
- Customer-managed KMS key (`alias/${name_prefix}-khalifa`) with rotation enabled. It encrypts DynamoDB, SQS, SNS, Secrets Manager, Neptune storage, and Neptune audit logs. Workload IRSA roles can decrypt that key.

The module does not create the EKS cluster, namespace, or Helm release. `khalifa-eks` installs the chart. A deployment repository pins a release tag and passes VPC, OIDC, and account inputs.

```hcl
module "khalifa_data" {
  source = "git::https://github.com/therandomsecurityguy/khalifa.git//deploy/terraform/khalifa-data?ref=v1.6.0"

  name_prefix            = "example"
  vpc_id                 = dependency.vpc.outputs.vpc_id
  vpc_cidr               = dependency.vpc.outputs.vpc_cidr_block
  private_subnet_ids     = dependency.vpc.outputs.private_subnets
  node_security_group_id = dependency.cluster.outputs.node_security_group_id
  oidc_provider_arn      = dependency.cluster.outputs.oidc_provider_arn
  home_account_id        = "123456789012"
  ui_base_url            = "https://khalifa.example.com"

  # Organization trail owned by the audit account. See "CloudTrail analyzer" below.
  cloudtrail_logs_bucket      = "example-cloudtrail-logs-audit-usw2"
  cloudtrail_organization_id  = "o-xxxxxxxxxx"
  cloudtrail_logs_kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-000000000000"
}
```

## CloudTrail analyzer

The trail bucket and its KMS key belong to the account that owns the organization trail, and this module cannot grant access to them. Before unsuspending the `cloudtrail-analyzer` CronJob, that account must allow the analyzer role (`arn:aws:iam::<home account>:role/<name_prefix>-khalifa-cloudtrail-analyzer`):

- Bucket policy: `s3:GetBucketLocation` and `s3:ListBucket` on the bucket, `s3:GetObject` on `<bucket>/AWSLogs/<organization id>/*`.
- Key policy: `kms:Decrypt` for the same role.

Until then the analyzer's Athena queries fail with `AccessDenied` on the trail objects.

`helm_values` is the non-secret chart fragment. Runtime secrets stay in Secrets Manager and reach pods through External Secrets (`khalifa-runtime`). The environment unit must not copy those values into Helm or Terraform state.
