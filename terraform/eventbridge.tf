# A member-account SCP in this Org fully denies cloudtrail:CreateTrail (no
# condition to work around - the org already runs its own centralized trail
# elsewhere), so we can't create a trail here at all. For now this means no
# data-event coverage (that needed our own trail's data-event selectors
# scoped to the bait buckets) and no cross-region coverage for management
# events (see below) - both deferred until there's a path around the SCP or
# through whoever manages the org's central trail.
#
# What's still available without a trail: EventBridge's direct, built-in
# CloudTrail integration ("AWS API Call via CloudTrail") delivers management
# events near-real-time, with no trail required - this is the same mechanism
# that powers the 90-day CloudTrail Event History every account gets for
# free. Its limitation is that events land on the bus in the region where
# the call happened; IAM/STS calls (sts:GetCallerIdentity - the main recon
# signal we expect) are global-service events and always land in us-east-1,
# so a single rule here catches that regardless of the caller's own region.
# Regional-service calls made outside this region won't be caught until this
# rule is replicated per-region.
resource "aws_cloudwatch_event_rule" "canary_api_calls" {
  name = "trippycreds-canary-api-calls"

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["IAMUser"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "event_consumer" {
  rule = aws_cloudwatch_event_rule.canary_api_calls.name
  arn  = aws_lambda_function.event_consumer.arn

  retry_policy {
    maximum_retry_attempts       = 3
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.event_consumer_dlq.arn
  }
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.event_consumer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.canary_api_calls.arn
}
