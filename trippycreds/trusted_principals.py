"""Registry of AWS principals explicitly trusted to call the cross-account
service API (POST /service/claim) without an operator in the loop - see
DESIGN.md's "Cross-account service claims" section for the full rationale.

Deliberately its own DynamoDB table, not a new item shape bolted onto
canary_keys: this is authorization data about *callers*, not canary state,
and keeping it separate means the claim-time authorization check is always a
single point lookup, independent of pool size.

A caller's SigV4-verified identity (`requestContext.identity.userArn` on the
service API's AWS_IAM-authorized route) is matched against `principal_arn`
here. AWS hands that identity to us in STS "assumed-role" form
(`arn:aws:sts::<acct>:assumed-role/<role-name>/<session>`) for any role-based
caller - which is nearly every real one (EC2 instance profiles, ECS task
roles, CodeBuild service roles, cross-account AssumeRole, ...) - not the bare
IAM role ARN an operator registers. `normalize_principal_arn` collapses that
back to the role ARN on every read and write, so registering
`arn:aws:iam::<acct>:role/build-server-role` once covers every session that
role ever assumes, regardless of session name.
"""

import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from .clients import Clients

logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_ACTIONS = ["claim"]

_ASSUMED_ROLE_RE = re.compile(r"^arn:aws:sts::(\d{12}):assumed-role/([^/]+)/.+$")


def normalize_principal_arn(arn: str) -> str:
    """Collapse an STS assumed-role ARN to the IAM role ARN it was assumed
    from. Any other ARN form (IAM user, already a bare role ARN) passes
    through unchanged.
    """
    match = _ASSUMED_ROLE_RE.match(arn)
    if not match:
        return arn
    account_id, role_name = match.groups()
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def register(
    clients: Clients,
    actor: dict,
    principal_arn: str,
    label: str,
    allowed_actions: Optional[List[str]] = None,
    environment: Optional[str] = None,
) -> dict:
    """Trust a principal to call the service API. Re-registering an ARN that
    already exists overwrites it in place (updates label/scope, and
    re-enables it if it had been disabled) - that's the intended way to
    change an entry's scope or bring a disabled one back, not an error.

    `environment`, if set, restricts this principal to claiming only with
    that exact `environment` value - the mechanism for scoping a build
    server to the one environment it's actually supposed to place canaries
    for. Leave it unset to allow any environment value.
    """
    item = {
        "principal_arn": normalize_principal_arn(principal_arn),
        "label": label,
        "allowed_actions": allowed_actions or list(DEFAULT_ALLOWED_ACTIONS),
        "enabled": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": actor,
    }
    if environment:
        item["environment"] = environment
    clients.trusted_principals_table.put_item(Item=item)
    return item


def disable(clients: Clients, actor: dict, principal_arn: str) -> Optional[dict]:
    """Soft-disable - the row stays for audit, same as a purged canary's row
    sticking around with status=deleted rather than being removed outright.
    """
    key = {"principal_arn": normalize_principal_arn(principal_arn)}
    existing = clients.trusted_principals_table.get_item(Key=key).get("Item")
    if existing is None:
        return None

    now = datetime.now(timezone.utc).isoformat()
    clients.trusted_principals_table.update_item(
        Key=key,
        UpdateExpression="SET enabled = :disabled, disabled_at = :now, disabled_by = :actor",
        ExpressionAttributeValues={":disabled": False, ":now": now, ":actor": actor},
    )
    existing.update(enabled=False, disabled_at=now, disabled_by=actor)
    return existing


def list_principals(clients: Clients) -> List[dict]:
    """Scan, not Query - this table has no access pattern that needs an
    index, and it's expected to stay small (one row per trusted build
    server/service, not per canary).
    """
    items: List[dict] = []
    kwargs: dict = {}
    while True:
        resp = clients.trusted_principals_table.scan(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def is_authorized(clients: Clients, caller_arn: str, action: str) -> Optional[dict]:
    """Returns the registry row if `caller_arn` is trusted for `action`, else
    None. Must be called with the raw, SigV4-verified ARN API Gateway attaches
    to the request (`requestContext.identity.userArn`) - never anything
    client-supplied.
    """
    item = clients.trusted_principals_table.get_item(
        Key={"principal_arn": normalize_principal_arn(caller_arn)}
    ).get("Item")
    if item is None or not item.get("enabled"):
        return None
    if action not in item.get("allowed_actions", []):
        return None
    return item
