mock_provider "aws" {
  override_during = plan

  mock_data "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
    }
  }

  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:us-west-2:111122223333:repository/khalifa"
      repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/khalifa"
    }
  }
}

run "publishing_boundary" {
  command = plan

  variables {
    name_prefix        = "example"
    github_repository  = "example/khalifa"
    github_oidc_subject_prefix = "repo:example@123456789/khalifa@987654321"
  }

  assert {
    condition = {
      for component, repository in aws_ecr_repository.images : component => repository.name
      } == {
      api         = "example-khalifa-api"
      ui          = "example-khalifa-ui"
      rule-runner = "example-khalifa-rule-runner"
    }
    error_message = "The module must create the three expected Khalifa repositories."
  }

  assert {
    condition = alltrue([
      for repository in aws_ecr_repository.images :
      repository.image_tag_mutability == "IMMUTABLE" &&
      repository.force_delete == false &&
      repository.encryption_configuration[0].encryption_type == "AES256" &&
      repository.image_scanning_configuration[0].scan_on_push
    ])
    error_message = "Khalifa repositories must use immutable tags, retain images, and scan on push."
  }

  assert {
    condition = jsondecode(aws_iam_role.github_actions_publish.assume_role_policy).Statement[0].Condition.StringEquals == {
      "token.actions.githubusercontent.com:aud"        = "sts.amazonaws.com"
      "token.actions.githubusercontent.com:repository" = "example/khalifa"
      "token.actions.githubusercontent.com:workflow"   = "Release"
    }
    error_message = "The publishing role trust must bind the expected audience, repository, and workflow."
  }

  assert {
    condition = toset(jsondecode(aws_iam_role.github_actions_publish.assume_role_policy).Statement[0].Condition.StringLike["token.actions.githubusercontent.com:sub"]) == toset([
      "repo:example@123456789/khalifa@987654321:ref:refs/heads/main",
      "repo:example@123456789/khalifa@987654321:ref:refs/tags/v*",
    ])
    error_message = "The publishing role trust must allow only main and version tags."
  }

  assert {
    condition = toset(jsondecode(aws_iam_role.github_actions_publish.assume_role_policy).Statement[0].Condition.StringLike["token.actions.githubusercontent.com:ref"]) == toset([
      "refs/heads/main",
      "refs/tags/v*",
    ])
    error_message = "The publishing role trust must bind the expected Git refs."
  }

  assert {
    condition = (
      length(jsondecode(aws_iam_role_policy.github_actions_publish.policy).Statement) == 2 &&
      jsondecode(aws_iam_role_policy.github_actions_publish.policy).Statement[0].Action == "ecr:GetAuthorizationToken" &&
      jsondecode(aws_iam_role_policy.github_actions_publish.policy).Statement[0].Resource == "*" &&
      length(jsondecode(aws_iam_role_policy.github_actions_publish.policy).Statement[1].Resource) == 3 &&
      alltrue([
        for resource in jsondecode(aws_iam_role_policy.github_actions_publish.policy).Statement[1].Resource : resource != "*"
      ]) &&
      toset(jsondecode(aws_iam_role_policy.github_actions_publish.policy).Statement[1].Action) == toset([
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
      ])
    )
    error_message = "The publishing role must have only the ECR actions used by the release workflow."
  }
}
