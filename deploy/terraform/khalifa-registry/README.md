# Khalifa registry Terraform module

This module creates the image-publishing boundary for Khalifa:

- immutable, scan-on-push ECR repositories for the API, UI, and rule runner
- a GitHub Actions role restricted to the Khalifa release workflow
- ECR-only publishing permissions scoped to those repositories

The module looks up the existing AWS IAM OIDC provider for GitHub Actions. It does not create the provider, deploy Khalifa, or manage GitHub repository variables. The publish role trust binds `github_repository` (`owner/name`); for repositories that use GitHub's immutable subject format (`repo:owner@ID/name@ID:ref:...`), pass it as `github_oidc_subject_prefix`.

A deployment repository owns the live Terragrunt unit, environment inputs, Terraform state, and apply. Its module source must pin a Khalifa release tag.

## Inputs

| Name                       | Required | Description                                                            |
| -------------------------- | -------- | ---------------------------------------------------------------------- |
| name_prefix                | yes      | Environment-specific resource prefix                                   |
| github_repository          | yes      | GitHub repository (`owner/name`) allowed to publish release images     |
| github_oidc_subject_prefix | no       | OIDC sub prefix override (defaults to `repo:<github_repository>`)      |
| tags                       | no       | Additional AWS resource tags                                           |

## Outputs

- repositories: repository ARN, name, and URL keyed by component
- github_actions_publish_role_arn
- github_actions_publish_role_name
