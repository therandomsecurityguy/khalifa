resource "aws_cognito_user_pool" "this" {
  name = local.name

  # Threat protection (advanced security) is a Plus-tier feature; ENFORCED
  # blocks compromised-credential sign-ins and adaptive challenges.
  user_pool_tier      = "PLUS"
  deletion_protection = "ACTIVE"

  mfa_configuration = "ON"
  username_attributes = [
    "email",
  ]
  auto_verified_attributes = [
    "email",
  ]

  software_token_mfa_configuration {
    enabled = true
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  password_policy {
    minimum_length    = 16
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = merge(var.tags, { Name = local.name })
}

resource "aws_cognito_user_pool_client" "this" {
  name         = "${local.name}-ui"
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret                      = false
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = [var.ui_base_url, "${var.ui_base_url}/"]
  logout_urls                          = [var.ui_base_url]
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}

resource "aws_cognito_user_group" "roles" {
  for_each = toset([
    "khalifa-admin",
    "khalifa-analyst",
    "khalifa-viewer",
  ])

  name         = each.value
  user_pool_id = aws_cognito_user_pool.this.id
  description  = "Khalifa ${trimprefix(each.value, "khalifa-")} role"
}
