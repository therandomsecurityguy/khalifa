variables {
  region                 = "us-west-2"
  cluster_name           = "example-cluster"
  vpc_id                 = "vpc-00000000000000000"
  vpc_cidr               = "10.0.0.0/16"
  private_subnet_ids     = ["subnet-00000000000000001", "subnet-00000000000000002"]
  node_security_group_id = "sg-00000000000000000"
  oidc_provider_arn      = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
  name_prefix            = "example"
  home_account_id        = "111122223333"
  collection_account_ids = ["111122223333"]
  collection_regions     = ["us-west-2"]
  ui_base_url            = "https://khalifa.example.com"
  github_repository      = "example/khalifa"
  image_digests = {
    api         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ui          = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    rule_runner = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }
}

mock_provider "aws" {
  override_during = plan

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }

  mock_data "aws_region" {
    defaults = {
      region = "us-west-2"
    }
  }

  mock_data "aws_regions" {
    defaults = {
      names = ["us-east-1", "us-west-2"]
    }
  }

  mock_data "aws_subnet" {
    defaults = {
      availability_zone = "us-west-2a"
    }
  }

  mock_data "aws_iam_openid_connect_provider" {
    defaults = {
      arn = "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE"
    }
  }

  mock_data "aws_eks_cluster" {
    defaults = {
      endpoint              = "https://EXAMPLE.gr7.us-west-2.eks.amazonaws.com"
      certificate_authority = [{ data = "Y2VydGlmaWNhdGU=" }]
    }
  }

  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:us-west-2:111122223333:repository/example-khalifa"
      repository_url = "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa"
    }
  }

  mock_resource "aws_neptune_cluster" {
    defaults = {
      endpoint            = "example-khalifa.cluster-example.us-west-2.neptune.amazonaws.com"
      cluster_resource_id = "cluster-ABCDEF"
    }
  }

  mock_resource "aws_cognito_user_pool" {
    defaults = {
      id = "us-west-2_example"
    }
  }

  mock_resource "aws_cognito_user_pool_client" {
    defaults = {
      id = "exampleclientid"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      url = "https://sqs.us-west-2.amazonaws.com/111122223333/example-khalifa-incremental.fifo"
      arn = "arn:aws:sqs:us-west-2:111122223333:example-khalifa-incremental.fifo"
    }
  }

  mock_resource "aws_dynamodb_table" {
    defaults = {
      arn = "arn:aws:dynamodb:us-west-2:111122223333:table/example-khalifa-issues"
    }
  }

  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:us-west-2:111122223333:example-khalifa-issues"
    }
  }

  mock_resource "aws_secretsmanager_secret" {
    defaults = {
      arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:example-khalifa/runtime"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111122223333:role/example-khalifa-workload"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000"
    }
  }
}

mock_provider "helm" {
  override_during = plan
}

run "wires_modules_and_chart_values" {
  command = plan

  assert {
    condition     = output.runtime_secret_name == "example-khalifa/runtime"
    error_message = "The runtime secret name must follow the module convention for External Secrets remoteRef keys."
  }

  assert {
    condition = (
      output.image_references.api == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
      output.image_references.ui == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" &&
      output.image_references.rule_runner == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    error_message = "Image references must come from the registry module repositories with the requested tag."
  }

  assert {
    condition = (
      output.chart_values.api.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" &&
      output.chart_values.ui.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" &&
      output.chart_values.ruleRunner.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.organizationCollector.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.incrementalCollector.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.graphWriter.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.compliance.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.cloudtrailAnalyzer.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.dspmScanner.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.policyEvaluator.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" &&
      output.chart_values.leastPrivilegeSweep.image == "111122223333.dkr.ecr.us-west-2.amazonaws.com/example-khalifa@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    error_message = "Every workload must pull the image tag; collector-style workloads share the rule-runner image."
  }

  assert {
    condition = length(output.chart_values.serviceAccounts) == 10 && alltrue([
      for key, service_account in output.chart_values.serviceAccounts :
      service_account.annotations["eks.amazonaws.com/role-arn"] == "arn:aws:iam::111122223333:role/example-khalifa-workload"
    ])
    error_message = "Every chart ServiceAccount must be annotated with its module-created IRSA role."
  }

  assert {
    condition = (
      output.chart_values.config.neptuneEndpoint == "wss://example-khalifa.cluster-example.us-west-2.neptune.amazonaws.com:8182/gremlin" &&
      output.chart_values.config.awsRegion == "us-west-2" &&
      output.chart_values.collection.homeAccountId == "111122223333" &&
      output.chart_values.collection.incrementalQueueUrl == "https://sqs.us-west-2.amazonaws.com/111122223333/example-khalifa-incremental.fifo"
    )
    error_message = "The data module helm_values must be merged into the chart values."
  }

  assert {
    condition = (
      output.chart_values.externalSecrets.enabled &&
      output.chart_values.externalSecrets.targetName == "khalifa-runtime" &&
      output.chart_values.externalSecrets.secretStore.service == "SecretsManager" &&
      output.chart_values.externalSecrets.secretStore.region == "us-west-2" &&
      output.chart_values.externalSecrets.secretStore.roleArn == aws_iam_role.external_secrets.arn
    )
    error_message = "External Secrets must read the runtime secret with the example-created IRSA role."
  }

  assert {
    condition = output.chart_values.externalSecrets.data == [
      {
        secretKey = "COLLECTOR_EXTERNAL_ID"
        remoteRef = {
          key      = "example-khalifa/runtime"
          property = "COLLECTOR_EXTERNAL_ID"
        }
      },
      {
        secretKey = "GRAPH_WRITER_TOKEN"
        remoteRef = {
          key      = "example-khalifa/runtime"
          property = "GRAPH_WRITER_TOKEN"
        }
      },
    ]
    error_message = "The ExternalSecret must map both runtime credential keys from Secrets Manager."
  }

  assert {
    condition = toset(output.chart_values.externalSecrets.mountIn) == toset([
      "organizationCollector",
      "incrementalCollector",
      "graphWriter",
      "cloudtrailAnalyzer",
      "dspmScanner",
    ])
    error_message = "Only workloads that consume runtime credentials may mount the ExternalSecret."
  }

  assert {
    condition = (
      output.helm_release != null &&
      output.helm_release.namespace == "khalifa"
    )
    error_message = "install_chart must install the release into the module namespace by default."
  }
}

run "skips_chart_when_disabled" {
  command = plan

  variables {
    install_chart = false
  }

  assert {
    condition     = output.helm_release == null
    error_message = "install_chart=false must not create a Helm release."
  }
}

run "external_secrets_role_trust" {
  command = plan

  assert {
    condition = jsondecode(aws_iam_role.external_secrets.assume_role_policy).Statement[0].Condition.StringEquals == {
      "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE:aud" = "sts.amazonaws.com"
      "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE:sub" = "system:serviceaccount:khalifa:khalifa-external-secrets"
    }
    error_message = "The External Secrets IRSA role must trust only the release's External Secrets ServiceAccount."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.external_secrets_runtime_secret.policy).Statement :
      statement.Action
      ])) == toset([
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "kms:Decrypt",
      "kms:DescribeKey",
    ])
    error_message = "The External Secrets role may only read the runtime secret and decrypt it with the data-plane CMK."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.external_secrets_runtime_secret.policy).Statement :
      statement.Resource
      ])) == toset([
      "arn:aws:secretsmanager:us-west-2:111122223333:secret:example-khalifa/runtime",
      "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000",
    ])
    error_message = "The External Secrets role must be scoped to the runtime secret and the data-plane CMK."
  }
}

run "rejects_bad_inputs" {
  command = plan

  variables {
    name_prefix     = "Bad_Prefix"
    home_account_id = "12345"
  }

  expect_failures = [var.name_prefix, var.home_account_id]
}
