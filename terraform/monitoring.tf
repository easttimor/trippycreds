# Without this, a persistently-failing event (e.g. a DynamoDB throttle that
# outlasts EventBridge's retries) just vanishes after retries exhaust, with
# no record it ever happened. The retry_policy caps how long EventBridge
# keeps trying before giving up and routing here instead.
resource "aws_sqs_queue" "event_consumer_dlq" {
  name                      = "trippycreds-event-consumer-dlq"
  message_retention_seconds = 1209600 # 14 days, the maximum
}

data "aws_iam_policy_document" "event_consumer_dlq_policy" {
  statement {
    sid    = "AllowEventBridgeSend"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.event_consumer_dlq.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.canary_api_calls.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "event_consumer_dlq" {
  queue_url = aws_sqs_queue.event_consumer_dlq.id
  policy    = data.aws_iam_policy_document.event_consumer_dlq_policy.json
}

# Fires if the event-consumer Lambda itself errors - this is about the
# detection pipeline's own health, not a canary trigger, so it reuses the
# existing alert topic but with a clearly distinct subject line.
resource "aws_cloudwatch_metric_alarm" "event_consumer_errors" {
  alarm_name          = "trippycreds-event-consumer-errors"
  alarm_description   = "TrippyCreds detection pipeline: the event-consumer Lambda is erroring - canary triggers may be getting missed."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.event_consumer.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.canary_alerts.arn]
  ok_actions          = [aws_sns_topic.canary_alerts.arn]
}

# Fires if anything actually lands in the DLQ - a stronger signal than the
# Errors alarm above, since it means retries were exhausted, not just that
# one attempt failed.
resource "aws_cloudwatch_metric_alarm" "event_consumer_dlq_depth" {
  alarm_name          = "trippycreds-event-consumer-dlq-depth"
  alarm_description   = "TrippyCreds detection pipeline: an event exhausted retries and landed in the dead-letter queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = aws_sqs_queue.event_consumer_dlq.name }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.canary_alerts.arn]
  ok_actions          = [aws_sns_topic.canary_alerts.arn]
}
