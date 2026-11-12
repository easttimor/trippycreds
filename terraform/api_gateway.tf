resource "aws_apigatewayv2_api" "api" {
  name          = "trippycreds-api"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["https://${aws_cloudfront_distribution.console.domain_name}"]
    allow_methods = ["GET", "POST", "OPTIONS"]
    allow_headers = ["authorization", "content-type"]
    max_age       = 300
  }
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.api.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "cognito"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.console.id]
    issuer   = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.console.id}"
  }
}

resource "aws_apigatewayv2_integration" "api_backend" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api_backend.invoke_arn
  payload_format_version = "2.0"
}

locals {
  api_routes = [
    "GET /canaries",
    "GET /canaries/{access_key_id}",
    "POST /canaries/claim",
    "POST /canaries/batch-create",
    "POST /canaries/purge-unclaimed",
    "POST /canaries/{access_key_id}/test-trigger",
    "GET /trusted-principals",
    "POST /trusted-principals",
    "POST /trusted-principals/disable",
    "POST /reconcile",
    "GET /reports/stale",
  ]
}

resource "aws_apigatewayv2_route" "api" {
  for_each  = toset(local.api_routes)
  api_id    = aws_apigatewayv2_api.api.id
  route_key = each.value
  target    = "integrations/${aws_apigatewayv2_integration.api_backend.id}"

  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
}

resource "aws_apigatewayv2_stage" "api" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true

  # Modest cap - this is a small internal console, not a public API. Mainly
  # a guardrail against a scripting mistake (or a compromised session)
  # hammering batch-create/purge in a loop.
  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_backend.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*/*"
}
