resource "helm_release" "khalifa" {
  name      = var.release_name
  namespace = var.namespace
  chart     = "${path.module}/../../helm/khalifa"

  values = [yamlencode(var.values)]

  atomic           = true
  cleanup_on_fail  = true
  create_namespace = false
  timeout          = var.timeout_seconds
  wait             = true
}
