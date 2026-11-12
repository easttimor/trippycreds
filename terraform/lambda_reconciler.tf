locals {
  reconciler_handler_files = fileset("${path.module}/../lambdas/reconciler", "**/*.py")

  reconciler_source_hash = sha1(join("", concat(
    [for f in local.trippycreds_files : filesha1("${path.module}/../trippycreds/${f}")],
    [for f in local.reconciler_handler_files : filesha1("${path.module}/../lambdas/reconciler/${f}")],
  )))

  reconciler_build_dir = "${path.module}/build/reconciler"
}

resource "null_resource" "lambda_build_reconciler" {
  triggers = {
    source_hash = local.reconciler_source_hash
  }

  provisioner "local-exec" {
    command = "${path.module}/../scripts/build_lambda.sh reconciler"
  }
}

data "archive_file" "reconciler" {
  type        = "zip"
  source_dir  = local.reconciler_build_dir
  output_path = "${path.module}/build/reconciler.zip"
  depends_on  = [null_resource.lambda_build_reconciler]
}

resource "aws_iam_role" "reconciler" {
  name               = "trippycreds-reconciler"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "reconciler_permissions" {
  statement {
    sid    = "DynamoReadOnly"
    effect = "Allow"
    # reconcile.run() only ever Querys the status-index GSI (via
    # iam_lifecycle.list_pool) across all three statuses - never Scan, never
    # a write.
    actions   = ["dynamodb:Query"]
    resources = [aws_dynamodb_table.canary_keys.arn, "${aws_dynamodb_table.canary_keys.arn}/index/*"]
  }

  # List-only IAM read access across the account - these actions don't
  # support resource-level or tag-condition scoping (same situation as the
  # existing IamAccountSummary statement in lambda_api_backend.tf). This
  # account has no workloads besides TrippyCreds (see DESIGN.md's "Account"
  # section), so every IAM User this reads back is expected to be a canary.
  statement {
    sid    = "IamReadOnly"
    effect = "Allow"
    actions = [
      "iam:ListUsers",
      "iam:ListUserTags",
      "iam:ListAttachedUserPolicies",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.canary_alerts.arn]
  }

  statement {
    sid    = "Logs"
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"]
  }
}

resource "aws_iam_role_policy" "reconciler" {
  name   = "permissions"
  role   = aws_iam_role.reconciler.id
  policy = data.aws_iam_policy_document.reconciler_permissions.json
}

resource "aws_lambda_function" "reconciler" {
  function_name = "trippycreds-reconciler"
  role          = aws_iam_role.reconciler.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  # Paginates every IAM user in the account (tags + attached policies per
  # user) - more headroom than event_consumer's 60s single-record handler.
  timeout          = 120
  filename         = data.archive_file.reconciler.output_path
  source_code_hash = data.archive_file.reconciler.output_base64sha256

  environment {
    variables = {
      CANARY_KEYS_TABLE   = aws_dynamodb_table.canary_keys.name
      CANARY_EVENTS_TABLE = aws_dynamodb_table.canary_events.name
      SNS_TOPIC_ARN       = aws_sns_topic.canary_alerts.arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "reconciler_schedule" {
  name                = "trippycreds-reconciler-schedule"
  schedule_expression = var.reconciler_schedule_expression
}

resource "aws_cloudwatch_event_target" "reconciler" {
  rule = aws_cloudwatch_event_rule.reconciler_schedule.name
  arn  = aws_lambda_function.reconciler.arn
}

resource "aws_lambda_permission" "allow_eventbridge_reconciler" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.reconciler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.reconciler_schedule.arn
}
