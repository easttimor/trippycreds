resource "aws_sns_topic" "canary_alerts" {
  name = "canary-alerts"
}

resource "aws_sns_topic_subscription" "canary_alert_emails" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.canary_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}
