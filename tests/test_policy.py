import json

from trippycreds import policy


def test_inline_policy_denies_everything_except_allowed_actions():
    document = json.loads(policy.inline_policy_document())
    statements = {s["Sid"]: s for s in document["Statement"]}

    allow = statements["AllowRecon"]
    assert allow["Effect"] == "Allow"
    assert allow["Action"] == list(policy.ALLOWED_ACTIONS)

    deny = statements["DenyEverythingElse"]
    assert deny["Effect"] == "Deny"
    assert deny["NotAction"] == list(policy.ALLOWED_ACTIONS)
    assert "Action" not in deny


def test_inline_policy_document_is_stable_json():
    first = policy.inline_policy_document()
    second = policy.inline_policy_document()
    assert first == second
