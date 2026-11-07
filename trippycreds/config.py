import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class Config:
    keys_table_name: str
    events_table_name: str
    sns_topic_arn: str
    aws_region: Optional[str] = None
    aws_profile: Optional[str] = None
    managed_by_tag_value: str = "platform-automation"

    @classmethod
    def from_env(cls) -> "Config":
        """Strict, env-var-only config - what the Lambda uses (set by Terraform)."""
        return cls(
            keys_table_name=_require_env("CANARY_KEYS_TABLE"),
            events_table_name=_require_env("CANARY_EVENTS_TABLE"),
            sns_topic_arn=_require_env("SNS_TOPIC_ARN"),
            aws_region=os.environ.get("AWS_REGION"),
            aws_profile=os.environ.get("AWS_PROFILE"),
            managed_by_tag_value=os.environ.get("MANAGED_BY_TAG_VALUE", "platform-automation"),
        )

    @classmethod
    def from_terraform(cls, terraform_dir: Optional[str] = None) -> "Config":
        """Reads `terraform output` so the local CLI needs no config file of its own -
        terraform.tfvars (gitignored) stays the only place instantiation values live.
        """
        terraform_dir = terraform_dir or str(Path(__file__).resolve().parent.parent / "terraform")
        try:
            result = subprocess.run(
                ["terraform", f"-chdir={terraform_dir}", "output", "-json"],
                capture_output=True,
                text=True,
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise RuntimeError(
                "could not read Terraform outputs from "
                f"{terraform_dir} - run `terraform apply` there first, or set "
                "CANARY_KEYS_TABLE/CANARY_EVENTS_TABLE/SNS_TOPIC_ARN env vars directly"
            ) from exc

        outputs = json.loads(result.stdout)
        try:
            return cls(
                keys_table_name=outputs["canary_keys_table"]["value"],
                events_table_name=outputs["canary_events_table"]["value"],
                sns_topic_arn=outputs["sns_topic_arn"]["value"],
                aws_region=outputs["aws_region"]["value"],
                aws_profile=outputs["aws_profile"]["value"],
                managed_by_tag_value=outputs["managed_by_tag_value"]["value"],
            )
        except KeyError as exc:
            raise RuntimeError(f"Terraform outputs are missing an expected key: {exc}") from exc

    @classmethod
    def load(cls) -> "Config":
        """Env vars win if set (useful for overrides/testing); otherwise read Terraform outputs."""
        if os.environ.get("CANARY_KEYS_TABLE"):
            return cls.from_env()
        return cls.from_terraform()


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value
