resource "aws_cognito_user_pool" "console" {
  name = "trippycreds-console"

  password_policy {
    minimum_length    = 12
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = false
  }

  # Admin-provisioned accounts only - no public self-service sign-up. Without
  # this, the Hosted UI's "Sign up" link is live and tries to send a
  # verification email through Cognito's default (low-quota, unreliable)
  # sender, which is what produced the generic Hosted UI error.
  admin_create_user_config {
    allow_admin_create_user_only = true
  }
}

resource "aws_cognito_user_pool_domain" "console" {
  domain       = "trippycreds-${random_id.bucket_suffix.hex}"
  user_pool_id = aws_cognito_user_pool.console.id
}

resource "aws_cognito_user_pool_client" "console" {
  name         = "console"
  user_pool_id = aws_cognito_user_pool.console.id

  generate_secret = false # public client - PKCE, not a confidential client

  # ALLOW_ADMIN_USER_PASSWORD_AUTH lets an operator holding AWS credentials in
  # this account mint tokens for a Cognito user directly (AdminInitiateAuth)
  # without a browser - used for scripted verification/testing. It doesn't
  # widen who can authenticate: it still requires the user's password, and
  # only principals who already have cognito-idp:AdminInitiateAuth in this
  # account (i.e. already-trusted admins) can invoke it at all.
  explicit_auth_flows = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

  allowed_oauth_flows                  = ["code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]

  # The SPA's own root doubles as the OAuth redirect URI (?code=... handled
  # client-side) - no separate /callback route needed, see console_site.tf.
  callback_urls = ["https://${aws_cloudfront_distribution.console.domain_name}/"]
  logout_urls   = ["https://${aws_cloudfront_distribution.console.domain_name}/"]

  prevent_user_existence_errors = "ENABLED"
}
