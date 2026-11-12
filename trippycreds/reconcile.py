"""Diff live IAM state against DynamoDB's canary_keys table, and separately
detect AWS's own automatic compromised-credential quarantine landing on a
canary - independent of, and often earlier than, our own CloudTrail-based
detection pipeline (see trippycreds/events.py).

DESIGN.md's "Tagging strategy" section describes the `ManagedBy`/`CostCenter`
tags as existing "so a reconciliation job can diff live IAM state against
DynamoDB without trusting DynamoDB alone" - this module is that job. It was
never built; DynamoDB has been the sole source of truth in practice, with no
check that IAM actually agrees with it.

This account is dedicated to TrippyCreds with no other workloads (see
DESIGN.md's "Account" section), so every IAM User here is expected to be a
canary - `list_users()` alone is a reasonable enumeration of candidates,
without needing to filter by tag first.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List

from . import iam_lifecycle
from .clients import Clients

logger = logging.getLogger(__name__)

# Substring, not an exact/version-pinned match - AWS has shipped
# AWSCompromisedKeyQuarantine, V2, and V3 managed policies so far; matching
# the stable substring means a future V4 is still caught without a code change.
QUARANTINE_POLICY_NAME_MARKER = "CompromisedKeyQuarantine"


def _paginate_users(clients: Clients) -> List[dict]:
    users = []
    for page in clients.iam.get_paginator("list_users").paginate():
        users.extend(page["Users"])
    return users


def _user_tags(clients: Clients, username: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for page in clients.iam.get_paginator("list_user_tags").paginate(UserName=username):
        for tag in page["Tags"]:
            tags[tag["Key"]] = tag["Value"]
    return tags


def _attached_policy_names(clients: Clients, username: str) -> List[str]:
    names: List[str] = []
    for page in clients.iam.get_paginator("list_attached_user_policies").paginate(UserName=username):
        names.extend(policy["PolicyName"] for policy in page["AttachedPolicies"])
    return names


def _expected_cost_center_tag(item: dict) -> str:
    if item["status"] == "unclaimed":
        return iam_lifecycle.UNCLAIMED_TAG_VALUE
    return f"CC-{item['batch_id']}"


def run(clients: Clients) -> dict:
    """Walk every live IAM user and every DynamoDB canary row once, cross-
    reference them, and return a report of drift/exposure findings. Read-only
    - never mutates IAM or DynamoDB.
    """
    active_rows = iam_lifecycle.list_pool(clients, "unclaimed") + iam_lifecycle.list_pool(clients, "claimed")
    deleted_rows = iam_lifecycle.list_pool(clients, "deleted")

    active_by_username = {item["iam_username"]: item for item in active_rows}
    deleted_by_username = {item["iam_username"]: item for item in deleted_rows}

    findings: List[dict] = []

    live_users = _paginate_users(clients)
    live_usernames = {user["UserName"] for user in live_users}

    # DynamoDB says this canary is live (unclaimed/claimed), but there's no
    # matching IAM user at all - the record and reality disagree about
    # whether this canary still exists.
    for item in active_rows:
        if item["iam_username"] not in live_usernames:
            findings.append(
                {
                    "type": "missing_in_iam",
                    "iam_username": item["iam_username"],
                    "access_key_id": item["access_key_id"],
                    "status": item["status"],
                    "detail": "DynamoDB row is active but no matching IAM user exists",
                }
            )

    # DynamoDB says this canary was torn down, but the IAM user is still
    # here - purge/retirement didn't finish tearing it down.
    for item in deleted_rows:
        if item["iam_username"] in live_usernames:
            findings.append(
                {
                    "type": "zombie_deleted",
                    "iam_username": item["iam_username"],
                    "access_key_id": item["access_key_id"],
                    "status": item["status"],
                    "detail": "DynamoDB row is status=deleted but the IAM user still exists",
                }
            )

    for user in live_users:
        username = user["UserName"]
        tags = _user_tags(clients, username)
        active_item = active_by_username.get(username)
        deleted_item = deleted_by_username.get(username)

        if active_item is None and deleted_item is None:
            findings.append(
                {
                    "type": "orphan_in_iam",
                    "iam_username": username,
                    "access_key_id": None,
                    "status": None,
                    "detail": "IAM user exists with no DynamoDB row at all",
                }
            )

        if iam_lifecycle.MANAGED_BY_TAG_KEY not in tags:
            findings.append(
                {
                    "type": "untagged_canary_user",
                    "iam_username": username,
                    "access_key_id": active_item["access_key_id"] if active_item else None,
                    "status": active_item["status"] if active_item else None,
                    "detail": f"IAM user has no {iam_lifecycle.MANAGED_BY_TAG_KEY} tag",
                }
            )

        if active_item is not None:
            expected = _expected_cost_center_tag(active_item)
            actual = tags.get(iam_lifecycle.STATUS_TAG_KEY)
            if actual != expected:
                findings.append(
                    {
                        "type": "tag_mismatch",
                        "iam_username": username,
                        "access_key_id": active_item["access_key_id"],
                        "status": active_item["status"],
                        "detail": f"{iam_lifecycle.STATUS_TAG_KEY} tag is {actual!r}, expected {expected!r}",
                    }
                )

        quarantine_policies = [
            name for name in _attached_policy_names(clients, username) if QUARANTINE_POLICY_NAME_MARKER in name
        ]
        if quarantine_policies:
            findings.append(
                {
                    "type": "quarantined",
                    "iam_username": username,
                    "access_key_id": active_item["access_key_id"] if active_item else None,
                    "status": active_item["status"] if active_item else None,
                    "detail": (
                        f"AWS attached {', '.join(quarantine_policies)} - this key was already flagged exposed "
                        "by AWS (e.g. GitHub secret scanning), independent of our own CloudTrail detection"
                    ),
                }
            )

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "iam_user_count": len(live_users),
        "ddb_row_count": len(active_rows) + len(deleted_rows),
        "findings": findings,
    }


def notify(clients: Clients, report: dict) -> None:
    """Publish to the existing canary-trigger SNS topic when the report has
    findings - reuses the same alert channel the detection pipeline's own
    health alarms already share (see terraform/monitoring.tf), with a
    distinct subject so it's obviously not a real canary trigger.
    """
    findings = report["findings"]
    if not findings:
        return
    subject = f"[RECONCILE] {len(findings)} finding(s) detected"
    clients.sns.publish(
        TopicArn=clients.config.sns_topic_arn,
        Subject=subject[:100],
        Message=json.dumps(report, indent=2),
    )
    logger.info("published reconciliation alert: %d finding(s)", len(findings))
