import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

import boto3
from boto3.dynamodb.conditions import Key
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from . import naming, policy
from .clients import Clients
from .events import MANUAL_TEST_USER_AGENT_PREFIX

logger = logging.getLogger(__name__)

MANAGED_BY_TAG_KEY = "ManagedBy"
STATUS_TAG_KEY = "CostCenter"
UNCLAIMED_TAG_VALUE = "CC-0000"
STATUS_INDEX = "status-index"

# unclaimed -> claimed is the live lifecycle; deleted is a terminal, soft-delete
# state - see purge_unclaimed. Kept as one tuple so the CLI and API handler can
# validate against it instead of each hard-coding their own copy.
VALID_STATUSES = ("unclaimed", "claimed", "deleted")


class NoUnclaimedCanariesError(RuntimeError):
    pass


class IamUserLimitReachedError(RuntimeError):
    pass


class CanaryNotLiveError(RuntimeError):
    pass


def _check_iam_user_headroom(clients: Clients, additional: int) -> None:
    """IAM hard-caps an account at 5,000 users (not an adjustable service quota),
    and that cap counts every IAM user in the account, not just canaries. Check
    before starting a batch instead of discovering it N users in - a batch that
    dies partway through with no indication of how far it got is worse than
    refusing up front.
    """
    summary = clients.iam.get_account_summary()["SummaryMap"]
    used = summary.get("Users", 0)
    quota = summary.get("UsersQuota", 5000)
    if used + additional > quota:
        raise IamUserLimitReachedError(
            f"creating {additional} more canary user(s) would exceed this account's IAM "
            f"user limit ({used}/{quota} used). Free up headroom first - "
            "purge_unclaimed()/`purge-unclaimed --execute` deletes the IAM users for "
            "canaries that were never claimed."
        )


def create_canary(clients: Clients, actor: dict, max_name_attempts: int = 5) -> dict:
    """Create one IAM user + access key, tag/police it, and record it unclaimed.

    `actor` identifies who/what asked for this (see trippycreds.actor) - stored
    on the row as `created_by`, independent of any free-text field.
    """
    tags = [
        {"Key": MANAGED_BY_TAG_KEY, "Value": clients.config.managed_by_tag_value},
        {"Key": STATUS_TAG_KEY, "Value": UNCLAIMED_TAG_VALUE},
    ]

    username = None
    for _ in range(max_name_attempts):
        candidate_name = naming.generate_username()
        try:
            clients.iam.create_user(UserName=candidate_name, Tags=tags)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityAlreadyExists":
                continue
            if code == "LimitExceeded":
                # The proactive check in batch_create() should normally catch this
                # first, but a concurrent caller (another batch-create running at
                # the same time) can still exhaust headroom between that check and
                # this call - surface it as the same typed error either way.
                raise IamUserLimitReachedError(
                    "AWS rejected IAM user creation: account is at its IAM user limit."
                ) from exc
            raise
        username = candidate_name
        break
    if username is None:
        raise RuntimeError("could not generate a unique IAM username after several attempts")

    try:
        clients.iam.put_user_policy(
            UserName=username,
            PolicyName=policy.INLINE_POLICY_NAME,
            PolicyDocument=policy.inline_policy_document(),
        )
        access_key = clients.iam.create_access_key(UserName=username)["AccessKey"]
    except ClientError:
        logger.exception("failed to finish provisioning %s, rolling back the user", username)
        # IAM refuses to delete a user that still has an inline policy or an
        # access key attached, so both have to go first - delete_user alone
        # would fail here and leave an orphaned user with no DynamoDB row.
        for existing_key in clients.iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
            _delete_access_key_if_present(clients, username, existing_key["AccessKeyId"])
        _delete_inline_policy_if_present(clients, username)
        _delete_user_if_present(clients, username)
        raise

    now = datetime.now(timezone.utc).isoformat()
    item = {
        "access_key_id": access_key["AccessKeyId"],
        "secret_access_key": access_key["SecretAccessKey"],
        "iam_username": username,
        "status": "unclaimed",
        "created_at": now,
        "created_by": actor,
        "trigger_count": 0,
    }
    clients.keys_table.put_item(Item=item)
    return item


def batch_create(clients: Clients, actor: dict, count: int) -> List[dict]:
    _check_iam_user_headroom(clients, count)
    return [create_canary(clients, actor) for _ in range(count)]


def claim(
    clients: Clients,
    actor: dict,
    placement_description: str,
    placed_by: str,
    environment: str,
    max_attempts: int = 10,
) -> dict:
    """Allocate any one unclaimed canary and attach placement metadata to it.

    `actor` is the authenticated caller (see trippycreds.actor), recorded as
    `claimed_by` - distinct from `placed_by`, which is a free-text note the
    caller supplies about the placement itself (e.g. a team name) and isn't
    verified against anything.
    """
    batch_id = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc).isoformat()

    for _ in range(max_attempts):
        candidates = clients.keys_table.query(
            IndexName=STATUS_INDEX,
            KeyConditionExpression=Key("status").eq("unclaimed"),
            Limit=1,
        )["Items"]
        if not candidates:
            raise NoUnclaimedCanariesError("no unclaimed canaries left in the pool")
        candidate = candidates[0]
        access_key_id = candidate["access_key_id"]

        try:
            clients.keys_table.update_item(
                Key={"access_key_id": access_key_id},
                UpdateExpression=(
                    "SET #status = :claimed, batch_id = :batch_id, claimed_at = :claimed_at, "
                    "placement_description = :placement_description, placed_by = :placed_by, "
                    "environment = :environment, claimed_by = :claimed_by"
                ),
                ConditionExpression="#status = :unclaimed",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":claimed": "claimed",
                    ":unclaimed": "unclaimed",
                    ":batch_id": batch_id,
                    ":claimed_at": now,
                    ":placement_description": placement_description,
                    ":placed_by": placed_by,
                    ":environment": environment,
                    ":claimed_by": actor,
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # someone else claimed this row between our query and our update; try another
                continue
            raise

        clients.iam.tag_user(
            UserName=candidate["iam_username"],
            Tags=[{"Key": STATUS_TAG_KEY, "Value": f"CC-{batch_id}"}],
        )
        candidate.update(
            status="claimed",
            batch_id=batch_id,
            claimed_at=now,
            placement_description=placement_description,
            placed_by=placed_by,
            environment=environment,
            claimed_by=actor,
        )
        return candidate

    raise NoUnclaimedCanariesError("could not claim a canary after retrying; high contention or pool exhausted")


def list_pool(clients: Clients, status: str) -> List[dict]:
    items: List[dict] = []
    kwargs = {"IndexName": STATUS_INDEX, "KeyConditionExpression": Key("status").eq(status)}
    while True:
        resp = clients.keys_table.query(**kwargs)
        items.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def get_canary_detail(clients: Clients, access_key_id: str) -> Optional[dict]:
    """The canary_keys row plus its full canary_events timeline, for the console's detail view."""
    item = clients.keys_table.get_item(Key={"access_key_id": access_key_id}).get("Item")
    if item is None:
        return None

    events: List[dict] = []
    kwargs = {"KeyConditionExpression": Key("access_key_id").eq(access_key_id)}
    while True:
        resp = clients.events_table.query(**kwargs)
        events.extend(resp["Items"])
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    item["events"] = sorted(events, key=lambda e: e["occurred_at"], reverse=True)
    return item


def trigger_test(clients: Clients, actor: dict, access_key_id: str) -> Optional[dict]:
    """Use a canary's own pulled-from-DynamoDB credentials to make one real,
    specially-marked sts:GetCallerIdentity call - proves the whole detection
    pipeline (EventBridge -> Lambda -> DynamoDB -> SNS) actually works, without
    the secret ever leaving the backend or this being mistaken for a real trigger.

    `actor` is who asked for this test - logged for audit, and returned as
    `triggered_by` (not to be confused with `caller_identity_arn`, which is the
    canary's *own* AWS identity, not the human/service that initiated the test).
    """
    item = clients.keys_table.get_item(Key={"access_key_id": access_key_id}).get("Item")
    if item is None:
        return None
    if "secret_access_key" not in item:
        raise CanaryNotLiveError(
            f"{item['iam_username']} (status={item.get('status')}) has no live credentials to "
            "test with - it was already purged/deleted."
        )

    test_session = boto3.Session(
        aws_access_key_id=item["access_key_id"],
        aws_secret_access_key=item["secret_access_key"],
    )
    sts = test_session.client(
        "sts",
        config=BotoConfig(user_agent_extra=f"{MANUAL_TEST_USER_AGENT_PREFIX}1.0"),
    )
    identity = sts.get_caller_identity()
    logger.info("manual test-trigger for %s (%s) initiated by %s", item["iam_username"], access_key_id, actor)
    return {
        "iam_username": item["iam_username"],
        "access_key_id": access_key_id,
        "caller_identity_arn": identity["Arn"],
        "triggered_by": actor,
    }


# Deleting one canary is ~4 sequential AWS API calls (1 conditional DynamoDB
# update + up to 3 IAM calls). Called synchronously through API Gateway, which
# hard-caps any integration at 30s regardless of the Lambda's own timeout - a
# big enough pool can blow through that mid-batch. Capping how many a single
# call processes keeps every call safely inside that window; the caller (CLI
# or console) just calls again if items remain.
DEFAULT_PURGE_BATCH_LIMIT = 25


def purge_unclaimed(
    clients: Clients, actor: dict, dry_run: bool = True, limit: Optional[int] = None
) -> List[dict]:
    """Tear down the IAM user + access key for up to `limit` unclaimed canaries,
    but keep the DynamoDB row - marked status=deleted - as a permanent record of
    what existed, rather than deleting it outright. Never touches claimed canaries.

    `actor` is recorded as `deleted_by` on each purged row.
    """
    items = list_pool(clients, "unclaimed")
    if dry_run:
        return items

    batch = items[: limit or DEFAULT_PURGE_BATCH_LIMIT]
    purged: List[dict] = []
    now = datetime.now(timezone.utc).isoformat()
    for item in batch:
        # Someone could claim this exact canary between the list_pool() read above
        # and this delete - a conditional update on the row re-checks "still
        # unclaimed" atomically, so a just-claimed canary's IAM user never gets
        # torn down out from under whoever claimed it. The secret is removed on
        # the way to deleted - once the IAM access key is gone it's dead weight
        # that only adds exposure if the table is ever read or exported.
        try:
            clients.keys_table.update_item(
                Key={"access_key_id": item["access_key_id"]},
                UpdateExpression=(
                    "SET #status = :deleted, deleted_at = :deleted_at, deleted_by = :deleted_by "
                    "REMOVE secret_access_key"
                ),
                ConditionExpression="#status = :unclaimed",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":deleted": "deleted",
                    ":deleted_at": now,
                    ":deleted_by": actor,
                    ":unclaimed": "unclaimed",
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                logger.info("%s was claimed before purge reached it, skipping", item["iam_username"])
                continue
            raise

        username = item["iam_username"]
        _delete_access_key_if_present(clients, username, item["access_key_id"])
        _delete_inline_policy_if_present(clients, username)
        _delete_user_if_present(clients, username)
        item["status"] = "deleted"
        item["deleted_at"] = now
        item["deleted_by"] = actor
        item.pop("secret_access_key", None)
        purged.append(item)

    return purged


def _delete_access_key_if_present(clients: Clients, username: str, access_key_id: str) -> None:
    try:
        clients.iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_inline_policy_if_present(clients: Clients, username: str) -> None:
    try:
        clients.iam.delete_user_policy(UserName=username, PolicyName=policy.INLINE_POLICY_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_user_if_present(clients: Clients, username: str) -> None:
    try:
        clients.iam.delete_user(UserName=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
