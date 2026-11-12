import pytest

from trippycreds import bake

ITEM = {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "s3cr3t"}


def test_dotenv_format():
    out = bake.render(ITEM, "dotenv")
    assert "AWS_ACCESS_KEY_ID=AKIAEXAMPLE" in out
    assert "AWS_SECRET_ACCESS_KEY=s3cr3t" in out
    assert "AWS_DEFAULT_REGION=" in out


def test_aws_credentials_file_format():
    out = bake.render(ITEM, "aws-credentials-file")
    assert "[default]" in out
    assert "aws_access_key_id = AKIAEXAMPLE" in out
    assert "aws_secret_access_key = s3cr3t" in out


def test_shell_export_format():
    out = bake.render(ITEM, "shell-export")
    assert "export AWS_ACCESS_KEY_ID=AKIAEXAMPLE" in out
    assert "export AWS_SECRET_ACCESS_KEY=s3cr3t" in out


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        bake.render(ITEM, "raw")
