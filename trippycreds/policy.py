import json

INLINE_POLICY_NAME = "canary-deny-all-except-recon"

# A canary user must still have zero *real* permissions after this policy is
# attached. Using Deny("*") + Allow("sts:GetCallerIdentity") would NOT work:
# IAM's explicit-deny-wins rule means the Deny("*") statement would also deny
# the one action we're trying to carve out. Instead, Deny targets everything
# via NotAction, excluding the carved-out actions, paired with an explicit
# Allow for just those actions (nothing is allowed by default anyway).
ALLOWED_ACTIONS = ("sts:GetCallerIdentity",)


def inline_policy_document() -> str:
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRecon",
                "Effect": "Allow",
                "Action": list(ALLOWED_ACTIONS),
                "Resource": "*",
            },
            {
                "Sid": "DenyEverythingElse",
                "Effect": "Deny",
                "NotAction": list(ALLOWED_ACTIONS),
                "Resource": "*",
            },
        ],
    }
    return json.dumps(document)
