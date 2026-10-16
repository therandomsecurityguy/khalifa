mock_provider "helm" {
  override_during = plan
}

run "release_defaults" {
  command = plan

  variables {
    namespace = "khalifa"
    values    = { api = { image = "example.com/khalifa-api:latest" } }
  }

  assert {
    condition     = helm_release.khalifa.name == "khalifa" && helm_release.khalifa.namespace == "khalifa"
    error_message = "The release must default to the khalifa name in the given namespace."
  }

  assert {
    condition     = endswith(helm_release.khalifa.chart, "helm/khalifa")
    error_message = "The release must install the version-matched chart in this repository."
  }

  assert {
    condition = (
      length(helm_release.khalifa.values) == 1 &&
      contains(helm_release.khalifa.values, yamlencode({ api = { image = "example.com/khalifa-api:latest" } }))
    )
    error_message = "The caller's values must be the only chart values passed to the release."
  }

  assert {
    condition = (
      helm_release.khalifa.atomic &&
      helm_release.khalifa.cleanup_on_fail &&
      !helm_release.khalifa.create_namespace &&
      helm_release.khalifa.wait &&
      helm_release.khalifa.timeout == 600
    )
    error_message = "The release must be atomic, wait for readiness, and never create the namespace."
  }
}

run "release_overrides" {
  command = plan

  variables {
    release_name    = "custom"
    namespace       = "custom-namespace"
    values          = {}
    timeout_seconds = 900
  }

  assert {
    condition = (
      helm_release.khalifa.name == "custom" &&
      helm_release.khalifa.namespace == "custom-namespace" &&
      helm_release.khalifa.timeout == 900
    )
    error_message = "release_name, namespace, and timeout_seconds must flow into the release."
  }
}

run "rejects_empty_namespace" {
  command = plan

  variables {
    namespace = "  "
    values    = {}
  }

  expect_failures = [var.namespace]
}

run "rejects_empty_release_name" {
  command = plan

  variables {
    release_name = " "
    namespace    = "khalifa"
    values       = {}
  }

  expect_failures = [var.release_name]
}
