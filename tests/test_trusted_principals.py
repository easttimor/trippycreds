from trippycreds import trusted_principals as tp


def test_normalize_assumed_role_arn_collapses_to_role_arn():
    assumed = "arn:aws:sts::123456789012:assumed-role/build-server-role/i-0abcd1234"
    assert tp.normalize_principal_arn(assumed) == "arn:aws:iam::123456789012:role/build-server-role"


def test_normalize_passes_through_non_assumed_role_arns():
    role_arn = "arn:aws:iam::123456789012:role/build-server-role"
    user_arn = "arn:aws:iam::123456789012:user/someone"
    assert tp.normalize_principal_arn(role_arn) == role_arn
    assert tp.normalize_principal_arn(user_arn) == user_arn


def test_register_then_is_authorized(clients):
    actor = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}
    role_arn = "arn:aws:iam::123456789012:role/build-server-role"
    tp.register(clients, actor, principal_arn=role_arn, label="ci-build-server")

    # assumed-role form of the same role should still be authorized
    assumed = "arn:aws:sts::123456789012:assumed-role/build-server-role/session-1"
    assert tp.is_authorized(clients, assumed, action="claim") is not None
    assert tp.is_authorized(clients, assumed, action="batch-create") is None


def test_is_authorized_respects_environment_scope(clients):
    actor = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}
    role_arn = "arn:aws:iam::123456789012:role/build-server-role"
    tp.register(clients, actor, principal_arn=role_arn, label="ci", environment="prod-honeypot")

    assert tp.is_authorized(clients, role_arn, action="claim") is not None


def test_disable_blocks_future_authorization(clients):
    actor = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}
    role_arn = "arn:aws:iam::123456789012:role/build-server-role"
    tp.register(clients, actor, principal_arn=role_arn, label="ci")
    assert tp.is_authorized(clients, role_arn, action="claim") is not None

    tp.disable(clients, actor, role_arn)
    assert tp.is_authorized(clients, role_arn, action="claim") is None


def test_disable_unknown_principal_returns_none(clients):
    actor = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}
    assert tp.disable(clients, actor, "arn:aws:iam::123456789012:role/never-registered") is None


def test_list_principals(clients):
    actor = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}
    tp.register(clients, actor, principal_arn="arn:aws:iam::123456789012:role/a", label="a")
    tp.register(clients, actor, principal_arn="arn:aws:iam::123456789012:role/b", label="b")

    items = tp.list_principals(clients)
    assert {item["label"] for item in items} == {"a", "b"}
