locals {
  trippycreds_files = fileset("${path.module}/../trippycreds", "**/*.py")
  handler_files     = fileset("${path.module}/../lambdas/event_consumer", "**/*.py")

  # Rebuild/re-upload the Lambda only when its source actually changes.
  lambda_source_hash = sha1(join("", concat(
    [for f in local.trippycreds_files : filesha1("${path.module}/../trippycreds/${f}")],
    [for f in local.handler_files : filesha1("${path.module}/../lambdas/event_consumer/${f}")],
  )))

  lambda_build_dir = "${path.module}/build/event_consumer"
}

resource "null_resource" "lambda_build_event_consumer" {
  triggers = {
    source_hash = local.lambda_source_hash
  }

  provisioner "local-exec" {
    command = "${path.module}/../scripts/build_lambda.sh event_consumer"
  }
}

data "archive_file" "event_consumer" {
  type        = "zip"
  source_dir  = local.lambda_build_dir
  output_path = "${path.module}/build/event_consumer.zip"
  depends_on  = [null_resource.lambda_build_event_consumer]
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "event_consumer" {
  name               = "trippycreds-event-consumer"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "event_consumer_permissions" {
  statement {
    sid    = "DynamoAccess"
    effect = "Allow"
    actions = [
      # process_cloudtrail_record() only ever does point lookups/writes on a
      # single access_key_id - no Query here, deliberately.
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [
      aws_dynamodb_table.canary_keys.arn,
      aws_dynamodb_table.canary_events.arn,
    ]
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

resource "aws_iam_role_policy" "event_consumer" {
  name   = "permissions"
  role   = aws_iam_role.event_consumer.id
  policy = data.aws_iam_policy_document.event_consumer_permissions.json
}

resource "aws_lambda_function" "event_consumer" {
  function_name    = "trippycreds-event-consumer"
  role             = aws_iam_role.event_consumer.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 60
  filename         = data.archive_file.event_consumer.output_path
  source_code_hash = data.archive_file.event_consumer.output_base64sha256

  environment {
    variables = {
      CANARY_KEYS_TABLE   = aws_dynamodb_table.canary_keys.name
      CANARY_EVENTS_TABLE = aws_dynamodb_table.canary_events.name
      SNS_TOPIC_ARN       = aws_sns_topic.canary_alerts.arn
    }
  }
}
