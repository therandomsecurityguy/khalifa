variable "release_name" {
  description = "Helm release name."
  type        = string
  default     = "khalifa"

  validation {
    condition     = length(trimspace(var.release_name)) > 0
    error_message = "release_name must not be empty."
  }
}

variable "namespace" {
  description = "Target Kubernetes namespace for the release."
  type        = string

  validation {
    condition     = length(trimspace(var.namespace)) > 0
    error_message = "namespace must not be empty."
  }
}

variable "values" {
  description = "Values passed to the Khalifa chart. The chart schema validates their structure."
  type        = any
}

variable "timeout_seconds" {
  description = "Maximum time to wait for a Helm operation."
  type        = number
  default     = 600

  validation {
    condition = (
      var.timeout_seconds == floor(var.timeout_seconds) &&
      var.timeout_seconds >= 1 &&
      var.timeout_seconds <= 3600
    )
    error_message = "timeout_seconds must be an integer between 1 and 3600."
  }
}
