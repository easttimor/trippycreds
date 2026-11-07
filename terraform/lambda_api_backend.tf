locals {
  api_backend_handler_files = fileset("${path.module}/../lambdas/api_backend", "**/*.py")

  api_backend_source_hash = sha1(join("", concat(
    [for f in local.trippycreds_files : filesha1("${path.module}/../trippycreds/${f}")],
    [for f in local.api_backend_handler_files : filesha1("${path.module}/../lambdas/api_backend/${f}")],
  )))

  api_backend_build_dir = "${path.module}/build/api_backend"
}

resource "null_resource" "lambda_build_api_backend" {
  triggers = {
    source_hash = local.api_backend_source_hash
  }

  provisioner "local-exec" {
    command = "${path.module}/../scripts/build_lambda.sh api_backend"
  }
}

data "archive_file" "api_backend" {
  type        = "zip"
  source_dir  = local.api_backend_build_dir
  output_path = "${path.module}/build/api_backend.zip"
  depends_on  = [null_resource.lambda_build_api_backend]
}

resource "aws_iam_role" "api_backend" {
  name               = "trippycreds-api-backend"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "api_backend_permissions" {
  statement {
    sid    = "DynamoAccess"
    effect = "Allow"
    actions = [
      # Deletion is always the soft-delete UpdateItem in purge_unclaimed() -
      # nothing in this codebase calls DeleteItem, so it's deliberately left
      # out here.
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
    ]
    resources = [
      aws_dynamodb_table.canary_keys.arn,
      "${aws_dynamodb_table.canary_keys.arn}/index/*",
      aws_dynamodb_table.canary_events.arn,
    ]
  }

  # GetAccountSummary is account-wide and doesn't support resource-level or
  # tag-condition scoping - it's a read-only call used only to check headroom
  # against the account's 5,000 IAM user limit before a batch-create.
  statement {
    sid       = "IamAccountSummary"
    effect    = "Allow"
    actions   = ["iam:GetAccountSummary"]
    resources = ["*"]
  }

  # CreateUser has no existing resource to scope by tag, so instead require
  # that whatever gets created is tagged as a canary (our own code already
  # does this, but this makes it an IAM-level guarantee, not just a
  # convention the code happens to follow).
  statement {
    sid       = "IamCreateCanaryUser"
    effect    = "Allow"
    actions   = ["iam:CreateUser"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/ManagedBy"
      values   = [var.managed_by_tag_value]
    }
  }

  # Everything else here can mutate or delete an IAM user - scoped to
  # user/* alone, that would let this role touch ANY IAM user in the
  # account, not just canaries. The ResourceTag condition means these
  # actions only ever succeed against a user already tagged as a canary,
  # so even a future bug that let a caller pass an arbitrary username
  # can't reach a real, non-canary IAM user.
  statement {
    sid    = "IamMutateCanaryUser"
    effect = "Allow"
    actions = [
      "iam:DeleteUser",
      "iam:TagUser",
      "iam:PutUserPolicy",
      "iam:DeleteUserPolicy",
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      # Needed by create_canary()'s own rollback path (trippycreds/iam_lifecycle.py)
      # when put_user_policy/create_access_key fails partway through - without
      # this, the rollback's list_access_keys call itself throws AccessDenied,
      # aborting cleanup and leaving an orphaned IAM user with no DynamoDB row.
      "iam:ListAccessKeys",
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:ResourceTag/ManagedBy"
      values   = [var.managed_by_tag_value]
    }
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

resource "aws_iam_role_policy" "api_backend" {
  name   = "permissions"
  role   = aws_iam_role.api_backend.id
  policy = data.aws_iam_policy_document.api_backend_permissions.json
}

resource "aws_lambda_function" "api_backend" {
  function_name    = "trippycreds-api-backend"
  role             = aws_iam_role.api_backend.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.api_backend.output_path
  source_code_hash = data.archive_file.api_backend.output_base64sha256

  environment {
    variables = {
      CANARY_KEYS_TABLE    = aws_dynamodb_table.canary_keys.name
      CANARY_EVENTS_TABLE  = aws_dynamodb_table.canary_events.name
      SNS_TOPIC_ARN        = aws_sns_topic.canary_alerts.arn
      MANAGED_BY_TAG_VALUE = var.managed_by_tag_value
    }
  }
}
