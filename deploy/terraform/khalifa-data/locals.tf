data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name = "${var.name_prefix}-khalifa"
  oidc_issuer = trimprefix(
    var.oidc_provider_arn,
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/"
  )
  service_accounts = {
    api                    = "${var.release_name}-api"
    rule-runner            = "${var.release_name}-rule-runner"
    organization-collector = "${var.release_name}-org-collector"
    incremental-collector  = "${var.release_name}-incremental"
    graph-writer           = "${var.release_name}-graph-writer"
    compliance             = "${var.release_name}-compliance"
    cloudtrail-analyzer    = "${var.release_name}-cloudtrail-analyzer"
    dspm-scanner           = "${var.release_name}-dspm-scanner"
    policy-evaluator       = "${var.release_name}-policy-evaluator"
    least-privilege-sweep  = "${var.release_name}-least-privilege-sweep"
  }
  collection_account_ids = distinct(concat([var.home_account_id], var.collection_account_ids))
}
