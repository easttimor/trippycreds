# Cross-account, machine-to-machine claim endpoint (e.g. a build server
# claiming a canary to inject into a host it manages) - see
# trippycreds/trusted_principals.py and DESIGN.md's "Cross-account service
# claims" section for the full design.
#
# Deliberately a *separate* REST API (aws_api_gateway_rest_api, "v1"), not a
# new route on the HTTP API in api_gateway.tf: HTTP APIs
# (aws_apigatewayv2_api) don't support resource policies at all, which means
# there is no way to permit a cross-account AWS_IAM-authorized caller on one
# - that's enforced at the AWS level, not a choice made here. REST APIs do
# support resource policies, so this one small API exists solely to carry
# that one route. The console's HTTP API is untouched.

resource "aws_api_gateway_rest_api" "service" {
  name = "trippycreds-service-api"
}

resource "aws_api_gateway_resource" "service" {
  rest_api_id = aws_api_gateway_rest_api.service.id
  parent_id   = aws_api_gateway_rest_api.service.root_resource_id
  path_part   = "service"
}

resource "aws_api_gateway_resource" "service_claim" {
  rest_api_id = aws_api_gateway_rest_api.service.id
  parent_id   = aws_api_gateway_resource.service.id
  path_part   = "claim"
}

resource "aws_api_gateway_method" "service_claim" {
  rest_api_id   = aws_api_gateway_rest_api.service.id
  resource_id   = aws_api_gateway_resource.service_claim.id
  http_method   = "POST"
  authorization = "AWS_IAM"
}

resource "aws_api_gateway_integration" "service_claim" {
  rest_api_id             = aws_api_gateway_rest_api.service.id
  resource_id             = aws_api_gateway_resource.service_claim.id
  http_method             = aws_api_gateway_method.service_claim.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.api_backend.invoke_arn
}

# Wide open on *who* may attempt to invoke (Principal = "*") - that's
# intentional, not an oversight. AWS_IAM authorization still requires a
# valid SigV4 signature from a real AWS principal; this policy only answers
# "is cross-account invocation permitted at all" (REST APIs deny that by
# default without an explicit resource policy grant). *Which* signed-in
# principal is actually allowed to do anything is decided entirely in
# application code, against the trusted-principals DynamoDB table - see
# trippycreds/trusted_principals.py and handler.py's _handle_service_claim.
# Narrowing this policy's Principal would only add a second, static
# allowlist that drifts from the real one in DynamoDB.
data "aws_iam_policy_document" "service_api_resource_policy" {
  statement {
    effect    = "Allow"
    actions   = ["execute-api:Invoke"]
    resources = ["${aws_api_gateway_rest_api.service.execution_arn}/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_api_gateway_rest_api_policy" "service" {
  rest_api_id = aws_api_gateway_rest_api.service.id
  policy      = data.aws_iam_policy_document.service_api_resource_policy.json
}

resource "aws_api_gateway_deployment" "service" {
  rest_api_id = aws_api_gateway_rest_api.service.id

  triggers = {
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.service_claim.id,
      aws_api_gateway_method.service_claim.id,
      aws_api_gateway_integration.service_claim.id,
      data.aws_iam_policy_document.service_api_resource_policy.json,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_api_gateway_method.service_claim,
    aws_api_gateway_integration.service_claim,
    aws_api_gateway_rest_api_policy.service,
  ]
}

resource "aws_api_gateway_stage" "service" {
  rest_api_id   = aws_api_gateway_rest_api.service.id
  deployment_id = aws_api_gateway_deployment.service.id
  stage_name    = "prod"
}

resource "aws_api_gateway_method_settings" "service" {
  rest_api_id = aws_api_gateway_rest_api.service.id
  stage_name  = aws_api_gateway_stage.service.stage_name
  method_path = "*/*"

  # Tighter than the console HTTP API's throttle - this is a handful of
  # trusted build servers claiming occasionally, not interactive console use.
  settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }
}

resource "aws_lambda_permission" "service_api_gateway" {
  statement_id  = "AllowServiceApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api_backend.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.service.execution_arn}/*/*"
}
