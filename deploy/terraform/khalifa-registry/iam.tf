data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "github_actions_publish" {
  name                 = local.github_actions_publish_role_name
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "GitHubActionsPublish"
      Effect = "Allow"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud"        = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:repository" = local.github_repository
          "token.actions.githubusercontent.com:workflow"   = "Release"
        }
        StringLike = {
          "token.actions.githubusercontent.com:ref" = local.github_actions_refs
          "token.actions.githubusercontent.com:sub" = local.github_actions_subjects
        }
      }
    }]
  })

  tags = merge(var.tags, {
    Name = local.github_actions_publish_role_name
  })
}

resource "aws_iam_role_policy" "github_actions_publish" {
  name = "${local.github_actions_publish_role_name}-inline"
  role = aws_iam_role.github_actions_publish.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "EcrAuthorization"
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      {
        Sid    = "PublishImages"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload",
          "ecr:DescribeImages",
          "ecr:DescribeRepositories",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ]
        Resource = values(aws_ecr_repository.images)[*].arn
      },
    ]
  })
}
