from boto3.dynamodb.conditions import Key

from trippycreds import iam_lifecycle
from trippycreds.events import MANUAL_TEST_USER_AGENT_PREFIX, process_cloudtrail_record

ACTOR = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}


def _cloudtrail_record(access_key_id, event_name="GetCallerIdentity", event_id="evt-1", user_agent="aws-cli/2.0"):
    return {
        "eventID": event_id,
        "eventName": event_name,
        "eventTime": "2026-01-01T00:00:00Z",
        "userAgent": user_agent,
        "sourceIPAddress": "203.0.113.5",
        "awsRegion": "us-east-1",
        "errorCode": "",
        "userIdentity": {"type": "IAMUser", "accessKeyId": access_key_id},
    }


def _events_for(clients, access_key_id):
    return clients.events_table.query(KeyConditionExpression=Key("access_key_id").eq(access_key_id))["Items"]


def test_matching_access_key_increments_rollup(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    record = _cloudtrail_record(item["access_key_id"])

    matched = process_cloudtrail_record(clients, record)

    assert matched is True
    row = clients.keys_table.get_item(Key={"access_key_id": item["access_key_id"]})["Item"]
    assert row["trigger_count"] == 1
    assert row["distinct_actions_seen"] == {"GetCallerIdentity"}
    assert row["last_triggered_at"] == "2026-01-01T00:00:00Z"
    assert len(_events_for(clients, item["access_key_id"])) == 1


def test_duplicate_event_id_is_idempotent(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    record = _cloudtrail_record(item["access_key_id"], event_id="evt-dup")

    assert process_cloudtrail_record(clients, record) is True
    assert process_cloudtrail_record(clients, record) is True  # retry delivery of the same event

    row = clients.keys_table.get_item(Key={"access_key_id": item["access_key_id"]})["Item"]
    assert row["trigger_count"] == 1  # not double-counted
    assert len(_events_for(clients, item["access_key_id"])) == 1


def test_manual_test_trigger_does_not_touch_rollup(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    record = _cloudtrail_record(item["access_key_id"], user_agent=f"aws-cli/2.0 {MANUAL_TEST_USER_AGENT_PREFIX}1.0")

    matched = process_cloudtrail_record(clients, record)

    assert matched is True
    row = clients.keys_table.get_item(Key={"access_key_id": item["access_key_id"]})["Item"]
    assert row.get("trigger_count", 0) == 0
    assert "last_triggered_at" not in row
    [event] = _events_for(clients, item["access_key_id"])
    assert event["is_manual_test"] is True


def test_unmatched_access_key_returns_false(clients):
    record = _cloudtrail_record("AKIANOTOURS")

    matched = process_cloudtrail_record(clients, record)

    assert matched is False
    assert _events_for(clients, "AKIANOTOURS") == []
