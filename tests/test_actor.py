import pytest

from trippycreds import actor


def test_from_cognito_claims_happy_path():
    result = actor.from_cognito_claims({"sub": "abc-123", "email": "operator@example.com"})
    assert result == {"type": "cognito_user", "id": "abc-123", "email": "operator@example.com"}


def test_from_cognito_claims_missing_sub_raises():
    with pytest.raises(actor.MissingActorError):
        actor.from_cognito_claims({"email": "operator@example.com"})


def test_from_cognito_claims_missing_email_is_none():
    result = actor.from_cognito_claims({"sub": "abc-123"})
    assert result == {"type": "cognito_user", "id": "abc-123", "email": None}


def test_from_aws_principal():
    arn = "arn:aws:iam::123456789012:user/operator"
    assert actor.from_aws_principal(arn) == {"type": "aws_principal", "id": arn}
