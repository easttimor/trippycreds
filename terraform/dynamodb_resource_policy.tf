# Table-level resource-based policies - the per-resource backstop called out
# as missing in DESIGN.md's "Defense in depth - protecting the DynamoDB
# tables directly" backlog item. The Org-level RCP there only blocks
# principals outside this AWS Org; it does nothing about an over-permissioned
# role or compromised session *inside* this account reading these tables
# directly via an ordinary identity policy, since identity and resource
# policies are combined with OR (an Allow from either side grants access)
# unless a policy carries an explicit Deny. Each statement below is exactly
# that explicit Deny, scoped to "anyone not already expected to touch this
# table" - the identity-side policies in lambda_api_backend.tf,
# lambda_event_consumer.tf and lambda_reconciler.tf still do the real
# least-privilege work of deciding which actions each expected principal
# gets.
#
# Caveat worth keeping in mind: unlike the Org RCP (enforced above IAM,
# binding even against this account's own admin/root), this is a resource
# policy this account's own admin can edit or delete at will - it narrows
# the blast radius of an over-permissioned *ordinary* role, but it is not a
# hard backstop against a fully compromised admin session the way the RCP
# is.
#
# Uses the aws:PrincipalArn condition key (StringNotLike) rather than
# NotPrincipal with literal role ARNs: NotPrincipal resolves role ARNs to
# their internal unique ID at policy-save time, so a role deleted and
# recreated under the same name/ARN would silently fall out of the
# allow-list. aws:PrincipalArn is a live string match against the caller's
# ARN, so it keeps working across role recreation.
#
# trippycreds-admin (the human AdministratorAccess SSO role) is
# deliberately NOT in any of these allow-lists, even though DESIGN.md's
# "Account" section treats SSO-role operator access as the expected human
# path - only trippycreds-deploy is. Any direct/manual DynamoDB access (the
# CLI, `aws dynamodb ...` by hand) has to go through the narrower deploy
# role, which is already the CLI's default profile (see
# trippycreds/config.py) - not raw admin. That also avoids hardcoding
# Identity Center's auto-generated permission-set role ARN suffix, which
# isn't a stable thing to match on in the first place.

locals {
  # Assumed via role-chaining from trippycreds-admin (see ~/.aws/config
  # locally - this role itself isn't Terraform-managed, same bootstrap
  # chicken-and-egg as the Org SCP/RCP in DESIGN.md). aws:PrincipalArn for
  # an assumed-role session resolves to the role's own ARN, not the
  # session/user ARN, so this stays correct no matter how many times or by
  # whom it's assumed.
  deploy_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/trippycreds-deploy"
}

# canary-keys: every live canary's access key ID/status plus, while
# unclaimed, the plaintext secret_access_key. Expected readers/writers are
# api_backend, event_consumer and reconciler (all three touch this table -
# see their respective aws_iam_policy_document resources) plus
# trippycreds-deploy (terraform apply, and the CLI's batch-create/claim/
# reconcile/stale-report commands).
data "aws_iam_policy_document" "canary_keys_resource_policy" {
  statement {
    sid    = "DenyUnlessExpectedPrincipal"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = ["dynamodb:*"]
    resources = [
      aws_dynamodb_table.canary_keys.arn,
      "${aws_dynamodb_table.canary_keys.arn}/index/*",
    ]

    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values = [
        aws_iam_role.api_backend.arn,
        aws_iam_role.event_consumer.arn,
        aws_iam_role.reconciler.arn,
        local.deploy_role_arn,
      ]
    }
  }
}

resource "aws_dynamodb_resource_policy" "canary_keys" {
  resource_arn = aws_dynamodb_table.canary_keys.arn
  policy       = data.aws_iam_policy_document.canary_keys_resource_policy.json
}

# canary-events: the CloudTrail-derived event log per canary key. Expected
# readers/writers are api_backend and event_consumer - reconciler never
# touches this table (it only Querys canary-keys, see lambda_reconciler.tf)
# - plus trippycreds-deploy for the CLI's stale-report command.
data "aws_iam_policy_document" "canary_events_resource_policy" {
  statement {
    sid    = "DenyUnlessExpectedPrincipal"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["dynamodb:*"]
    resources = [aws_dynamodb_table.canary_events.arn]

    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values = [
        aws_iam_role.api_backend.arn,
        aws_iam_role.event_consumer.arn,
        local.deploy_role_arn,
      ]
    }
  }
}

resource "aws_dynamodb_resource_policy" "canary_events" {
  resource_arn = aws_dynamodb_table.canary_events.arn
  policy       = data.aws_iam_policy_document.canary_events_resource_policy.json
}

# trusted-principals: the cross-account claim allowlist. Worth guarding the
# same way even though DESIGN.md's backlog note only names canary-keys/
# canary-events - a role that could write here could register itself as a
# trusted cross-account claimant, which is its own kind of sensitive. Only
# api_backend touches this table (the service-claim API path - see
# rest_api_service.tf/trippycreds/trusted_principals.py), plus
# trippycreds-deploy for the CLI's trust-registry management commands.
data "aws_iam_policy_document" "trusted_principals_resource_policy" {
  statement {
    sid    = "DenyUnlessExpectedPrincipal"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["dynamodb:*"]
    resources = [aws_dynamodb_table.trusted_principals.arn]

    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values = [
        aws_iam_role.api_backend.arn,
        local.deploy_role_arn,
      ]
    }
  }
}

resource "aws_dynamodb_resource_policy" "trusted_principals" {
  resource_arn = aws_dynamodb_table.trusted_principals.arn
  policy       = data.aws_iam_policy_document.trusted_principals_resource_policy.json
}
