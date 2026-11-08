output "demo_bucket_name" {
  value = aws_s3_bucket.demo.bucket
}

output "canary_keys_table" {
  value = aws_dynamodb_table.canary_keys.name
}

output "canary_events_table" {
  value = aws_dynamodb_table.canary_events.name
}

output "sns_topic_arn" {
  value = aws_sns_topic.canary_alerts.arn
}

output "trusted_principals_table" {
  value = aws_dynamodb_table.trusted_principals.name
}

# Where a trusted build server/service points sts/execute-api SigV4 requests
# to claim a canary directly - see DESIGN.md's "Cross-account service
# claims" section. Deliberately not the same as api_base_url (that's the
# Cognito-authorized console API).
output "service_claim_api_url" {
  value = "${aws_api_gateway_stage.service.invoke_url}/service/claim"
}

output "event_consumer_function_name" {
  value = aws_lambda_function.event_consumer.function_name
}

output "console_url" {
  value = "https://${aws_cloudfront_distribution.console.domain_name}/"
}

output "api_base_url" {
  value = aws_apigatewayv2_stage.api.invoke_url
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.console.id
}

output "cognito_client_id" {
  value = aws_cognito_user_pool_client.console.id
}

output "cognito_domain" {
  value = "https://${aws_cognito_user_pool_domain.console.domain}.auth.${var.aws_region}.amazoncognito.com"
}

# Pass-through outputs so the local CLI can discover its own runtime config
# via `terraform output -json` instead of needing a second config file.
output "aws_region" {
  value = var.aws_region
}

output "aws_profile" {
  value = var.aws_profile
}

output "managed_by_tag_value" {
  value = var.managed_by_tag_value
}
