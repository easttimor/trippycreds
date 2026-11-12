variable "aws_profile" {
  description = "AWS CLI/SSO profile with access to the dedicated trippycreds account."
  type        = string
}

variable "expected_account_id" {
  description = "Account ID this is expected to deploy into - a safety check against the wrong profile/account."
  type        = string
}

variable "aws_region" {
  description = "Region to deploy the core infrastructure into."
  type        = string
  default     = "us-east-1"
}

variable "alert_emails" {
  description = "Email addresses to subscribe to the canary-trigger SNS topic."
  type        = list(string)
}

variable "managed_by_tag_value" {
  description = "Value for the ManagedBy tag applied to every canary IAM user and bait resource."
  type        = string
  default     = "platform-automation"
}

variable "reconciler_schedule_expression" {
  description = "EventBridge schedule expression for the IAM<->DynamoDB reconciliation Lambda."
  type        = string
  default     = "rate(1 day)"
}
