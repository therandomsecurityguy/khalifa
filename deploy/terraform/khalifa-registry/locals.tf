locals {
  name              = "${var.name_prefix}-khalifa"
  github_repository = var.github_repository
  repository_names = {
    api         = "${local.name}-api"
    ui          = "${local.name}-ui"
    rule-runner = "${local.name}-rule-runner"
  }
  github_actions_publish_role_name = "${local.name}-gha-publish"
  github_actions_refs = [
    "refs/heads/main",
    "refs/tags/v*",
  ]
  # GitHub OIDC sub prefix. Defaults to the classic repo:owner/name form; supply
  # github_oidc_subject_prefix to use GitHub's immutable owner/repo ID form
  # (repo:owner@ID/name@ID) for repositories created after 2026-07-15.
  github_oidc_subject_prefix = (
    var.github_oidc_subject_prefix != ""
    ? var.github_oidc_subject_prefix
    : "repo:${var.github_repository}"
  )
  github_actions_subjects = [
    for ref in local.github_actions_refs : "${local.github_oidc_subject_prefix}:ref:${ref}"
  ]
}
