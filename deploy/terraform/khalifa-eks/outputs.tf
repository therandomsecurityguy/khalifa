output "release" {
  description = "Installed Khalifa Helm release identity and status."
  value = {
    name      = helm_release.khalifa.name
    namespace = helm_release.khalifa.namespace
    status    = helm_release.khalifa.status
  }
}
