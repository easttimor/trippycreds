"""Render a claimed canary's credentials as a plausible-looking leaked
artifact instead of a bare key pair - a finder is more likely to treat a
believable .env/credentials file as a real secret than two isolated
strings with no surrounding context.

Pure formatting only - no AWS calls, nothing persisted. The secret material
comes straight from the DynamoDB item `claim()`/`get_canary_detail()`
already returned.
"""

FORMATS = ("dotenv", "aws-credentials-file", "shell-export")

_DEFAULT_REGION = "us-east-1"


def render(item: dict, fmt: str) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"fmt must be one of {FORMATS}, got {fmt!r}")

    access_key_id = item["access_key_id"]
    secret_access_key = item["secret_access_key"]
    region = item.get("environment_region") or _DEFAULT_REGION

    if fmt == "dotenv":
        return (
            f"AWS_ACCESS_KEY_ID={access_key_id}\n"
            f"AWS_SECRET_ACCESS_KEY={secret_access_key}\n"
            f"AWS_DEFAULT_REGION={region}\n"
        )
    if fmt == "aws-credentials-file":
        return (
            "[default]\n"
            f"aws_access_key_id = {access_key_id}\n"
            f"aws_secret_access_key = {secret_access_key}\n"
            f"region = {region}\n"
        )
    # shell-export
    return (
        f"export AWS_ACCESS_KEY_ID={access_key_id}\n"
        f"export AWS_SECRET_ACCESS_KEY={secret_access_key}\n"
        f"export AWS_DEFAULT_REGION={region}\n"
    )
