output "namespace" {
  description = "Kubernetes namespace that must exist before the chart is installed."
  value       = var.namespace
}

output "neptune_endpoint" {
  description = "Gremlin WSS endpoint for Khalifa workloads."
  value       = module.khalifa_data.neptune_endpoint
}

output "runtime_secret_name" {
  description = "Secrets Manager name of the runtime secret External Secrets reads."
  value       = module.khalifa_data.runtime_secret_name
}

output "chart_values" {
  description = "Non-secret chart values passed to the Helm release. Runtime credentials stay in Secrets Manager."
  value       = local.chart_values
}

output "image_references" {
  description = "Image references the chart pulls. Push these before installing the release."
  value = {
    api         = local.api_image
    ui          = local.ui_image
    rule_runner = local.rule_runner_image
  }
}

output "registry_repositories" {
  description = "ECR repositories keyed by component."
  value       = module.khalifa_registry.repositories
}

output "github_actions_publish_role_arn" {
  description = "Role ARN the Khalifa release workflow uses to publish images."
  value       = module.khalifa_registry.github_actions_publish_role_arn
}

output "cognito" {
  description = "Cognito user pool and client for the UI and API."
  value       = module.khalifa_data.cognito
}

output "tables" {
  description = "DynamoDB table names keyed by workload use."
  value       = module.khalifa_data.tables
}

output "helm_release" {
  description = "Installed Helm release, when install_chart is true."
  value       = var.install_chart ? module.khalifa_eks[0].release : null
}
