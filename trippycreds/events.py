import json
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from botocore.exceptions import ClientError

from .clients import Clients

logger = logging.getLogger(__name__)

MANUAL_TEST_USER_AGENT_PREFIX = "TrippyCreds-ManualTest/"

# Bumped if the SNS payload's shape changes in a way a consumer might need to
# branch on - keep this in lockstep with whatever subscribers parse.
SCHEMA_VERSION = "1"


def process_cloudtrail_record(clients: Clients, record: dict) -> bool:
    """Match a single CloudTrail record against tracked canaries; record + notify on a hit.

    Returns True if the record's access key belongs to a tracked canary.
    """
    access_key_id = record.get("userIdentity", {}).get("accessKeyId")
    if not access_key_id:
        return False

    item = clients.keys_table.get_item(Key={"access_key_id": access_key_id}).get("Item")
    if item is None:
        return False  # not one of ours

    occurred_at = record.get("eventTime")
    event_id = record.get("eventID") or str(uuid.uuid4())
    event_name = record.get("eventName")
    user_agent = record.get("userAgent") or ""
    # botocore's user_agent_extra appends rather than replaces, so the marker
    # could land anywhere in the final string - check containment, not prefix.
    is_manual_test = MANUAL_TEST_USER_AGENT_PREFIX in user_agent

    # CloudTrail's eventTime has one-second resolution, so two real actions in
    # the same second would collide on a plain-timestamp sort key; the event's
    # own eventID makes this unique. The conditional write also makes this
    # idempotent - if EventBridge retries this same event (e.g. because the
    # SNS publish below failed transiently last time), the retry is a no-op
    # instead of double-counting trigger_count.
    event_key = f"{occurred_at}#{event_id}"
    try:
        clients.events_table.put_item(
            Item={
                "access_key_id": access_key_id,
                "event_time": event_key,
                "occurred_at": occurred_at,
                "event_id": event_id,
                "event_name": event_name,
                "source_ip": record.get("sourceIPAddress"),
                "user_agent": user_agent,
                "error_code": record.get("errorCode", ""),
                "aws_region": record.get("awsRegion"),
                "is_manual_test": is_manual_test,
            },
            ConditionExpression="attribute_not_exists(event_time)",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
            logger.info("duplicate delivery of event %s for %s, skipping", event_id, access_key_id)
            return True
        raise

    if is_manual_test:
        # Proves the pipeline works end to end without polluting the real
        # attacker-attribution signal: no rollup update, no "canary
        # triggered" alert - just a clearly-labeled row in the timeline.
        _notify(clients, item, record, is_manual_test=True, rollup=None)
        logger.info("manual test trigger recorded: %s (%s)", item["iam_username"], access_key_id)
        return True

    # ReturnValues gives back the post-increment counters in the same round
    # trip, so the alert reports this event's real trigger_count/distinct
    # actions instead of the stale snapshot read before the update.
    update_resp = clients.keys_table.update_item(
        Key={"access_key_id": access_key_id},
        UpdateExpression=(
            "ADD distinct_actions_seen :action, trigger_count :one SET last_triggered_at = :occurred_at"
        ),
        ExpressionAttributeValues={
            ":action": {event_name},
            ":one": 1,
            ":occurred_at": occurred_at,
        },
        ReturnValues="UPDATED_NEW",
    )

    _notify(clients, item, record, is_manual_test=False, rollup=update_resp.get("Attributes", {}))
    logger.info("canary triggered: %s (%s) action=%s", item["iam_username"], access_key_id, event_name)
    return True


def _json_default(value):
    """json.dumps default= for the DynamoDB-native types boto3's resource API
    returns (Decimal for numbers, set for String/Number Sets)."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"object of type {type(value).__name__} is not JSON serializable")


def _build_payload(item: dict, record: dict, *, is_manual_test: bool, rollup: Optional[dict]) -> dict:
    """Everything known about a tripped credential, as one JSON-serializable
    dict. The consuming end of the SNS topic is a system, not a human, so this
    is deliberately structured data rather than prose, and the key set is
    identical regardless of `is_manual_test` - a downstream parser should
    never need an `if "note" in payload` branch to know what shape to expect.
    `event_type`/`is_manual_test` are the intended differentiator (also mirrored
    onto the SNS message attribute so subscribers can filter without parsing
    the body at all).

    `canary` is built from an explicit allowlist of `item` fields (never
    passed through wholesale) so a stray `secret_access_key` can never end up
    in an alert. `trigger`, by contrast, includes the raw CloudTrail record
    verbatim alongside a curated subset of commonly-used fields, since the
    record itself holds nothing secret and "all available information" means
    not silently dropping whatever fields CloudTrail happens to send.
    """
    user_identity = record.get("userIdentity") or {}
    payload = {
        "schema_version": SCHEMA_VERSION,
        "event_type": "manual_test_trigger" if is_manual_test else "canary_triggered",
        "is_manual_test": is_manual_test,
        "notified_at": datetime.now(timezone.utc).isoformat(),
        "canary": {
            "iam_username": item.get("iam_username"),
            "access_key_id": item.get("access_key_id"),
            "status": item.get("status"),
            "batch_id": item.get("batch_id"),
            "created_at": item.get("created_at"),
            "created_by": item.get("created_by"),
            "claimed_at": item.get("claimed_at"),
            "claimed_by": item.get("claimed_by"),
            "placement_description": item.get("placement_description"),
            "placed_by": item.get("placed_by"),
            "environment": item.get("environment"),
        },
        "trigger": {
            "event_id": record.get("eventID"),
            "event_name": record.get("eventName"),
            "event_time": record.get("eventTime"),
            "event_source": record.get("eventSource"),
            "event_category": record.get("eventCategory"),
            "aws_region": record.get("awsRegion"),
            "source_ip": record.get("sourceIPAddress"),
            "user_agent": record.get("userAgent"),
            "error_code": record.get("errorCode") or None,
            "error_message": record.get("errorMessage") or None,
            "request_id": record.get("requestID"),
            "recipient_account_id": record.get("recipientAccountId"),
            "read_only": record.get("readOnly"),
            "management_event": record.get("managementEvent"),
            "caller_identity": {
                "type": user_identity.get("type"),
                "principal_id": user_identity.get("principalId"),
                "arn": user_identity.get("arn"),
                "account_id": user_identity.get("accountId"),
            },
            "request_parameters": record.get("requestParameters"),
            "response_elements": record.get("responseElements"),
            # Full raw record, unfiltered - belt-and-suspenders against the
            # curated fields above missing something (e.g. additionalEventData,
            # resources, apiVersion, vpcEndpointId) that a downstream consumer
            # still needs.
            "raw_event": record,
        },
        "rollup": (
            {
                "trigger_count": rollup.get("trigger_count"),
                "distinct_actions_seen": rollup.get("distinct_actions_seen"),
                "last_triggered_at": rollup.get("last_triggered_at"),
            }
            if rollup is not None
            else None
        ),
        # Always present (never conditionally added) so real and test payloads
        # share one schema; null except on manual test triggers, where it
        # explains the rollup-is-null side effect of marking.
        "note": (
            "Manual pipeline test triggered from the console/CLI, not a real "
            "detection - rollup counters were intentionally not incremented, "
            "so `rollup` is null."
            if is_manual_test
            else None
        ),
    }
    return payload


def _notify(clients: Clients, item: dict, record: dict, *, is_manual_test: bool, rollup: Optional[dict]) -> None:
    payload = _build_payload(item, record, is_manual_test=is_manual_test, rollup=rollup)
    subject = (
        f"[TEST] Canary pipeline check via {item['iam_username']}"
        if is_manual_test
        else f"Canary triggered: {item['iam_username']}"
    )
    clients.sns.publish(
        TopicArn=clients.config.sns_topic_arn,
        # SNS subjects are capped at 100 chars; usernames are short and fixed-
        # format, but slice defensively rather than let publish() ever 400.
        Subject=subject[:100],
        Message=json.dumps(payload, indent=2, default=_json_default),
        MessageAttributes={
            "is_manual_test": {
                "DataType": "String",
                "StringValue": "true" if is_manual_test else "false",
            },
        },
    )
