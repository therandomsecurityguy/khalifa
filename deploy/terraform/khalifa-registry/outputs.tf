output "repositories" {
  description = "Khalifa image repository identifiers keyed by component."
  value = {
    for component, repository in aws_ecr_repository.images : component => {
      arn  = repository.arn
      name = repository.name
      url  = repository.repository_url
    }
  }
}

output "github_actions_publish_role_arn" {
  description = "Role ARN used by the Khalifa release workflow to publish images."
  value       = aws_iam_role.github_actions_publish.arn
}

output "github_actions_publish_role_name" {
  description = "Role name used by the Khalifa release workflow to publish images."
  value       = aws_iam_role.github_actions_publish.name
}
