provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region

  default_tags {
    tags = {
      ManagedBy = var.managed_by_tag_value
      Project   = "trippycreds"
    }
  }
}

data "aws_caller_identity" "current" {}

# Safety net against applying with the wrong AWS profile: fails fast instead
# of silently provisioning canary infrastructure into the wrong account.
check "correct_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.expected_account_id
    error_message = "This profile resolves to account ${data.aws_caller_identity.current.account_id}, but expected_account_id is set to ${var.expected_account_id}. Check var.aws_profile."
  }
}
