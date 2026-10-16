variable "name_prefix" {
  description = "Environment-specific prefix for Khalifa registry resources."
  type        = string

  validation {
    condition = (
      length(var.name_prefix) <= 32 &&
      can(regex("^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", var.name_prefix))
    )
    error_message = "name_prefix must be 1-32 lowercase alphanumeric or hyphen characters and cannot end with a hyphen."
  }
}

variable "github_repository" {
  description = "GitHub repository (owner/name) allowed to publish Khalifa release images."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be in owner/name form."
  }
}

variable "github_oidc_subject_prefix" {
  description = "Override for the GitHub OIDC sub prefix, for example GitHub's immutable repo:owner@ID/name@ID form. Defaults to the github_repository value with a repo: prefix."
  type        = string
  default     = ""

  validation {
    condition     = var.github_oidc_subject_prefix == "" || can(regex("^repo:", var.github_oidc_subject_prefix))
    error_message = "github_oidc_subject_prefix must start with repo:."
  }
}

variable "tags" {
  description = "Additional tags for Khalifa registry resources."
  type        = map(string)
  default     = {}
}
