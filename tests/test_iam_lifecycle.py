from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from trippycreds import iam_lifecycle

ACTOR = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}


def _conditional_check_failed():
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "contended"}},
        "UpdateItem",
    )


def test_create_canary_returns_expected_fields(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)

    assert item["status"] == "unclaimed"
    assert item["trigger_count"] == 0
    assert item["created_by"] == ACTOR
    assert item["access_key_id"]
    assert item["secret_access_key"]

    stored = clients.keys_table.get_item(Key={"access_key_id": item["access_key_id"]})["Item"]
    assert stored["iam_username"] == item["iam_username"]

    tags = {t["Key"]: t["Value"] for t in clients.iam.list_user_tags(UserName=item["iam_username"])["Tags"]}
    assert tags["ManagedBy"] == "platform-automation"
    assert tags["CostCenter"] == "CC-0000"


def test_batch_create_headroom_check_raises_when_over_limit(clients):
    with patch.object(
        clients.iam, "get_account_summary", return_value={"SummaryMap": {"Users": 4999, "UsersQuota": 5000}}
    ):
        with pytest.raises(iam_lifecycle.IamUserLimitReachedError):
            iam_lifecycle._check_iam_user_headroom(clients, 2)


def test_batch_create_headroom_check_ok_under_limit(clients):
    with patch.object(
        clients.iam, "get_account_summary", return_value={"SummaryMap": {"Users": 10, "UsersQuota": 5000}}
    ):
        iam_lifecycle._check_iam_user_headroom(clients, 2)  # must not raise


def test_batch_create_creates_requested_count(clients):
    created = iam_lifecycle.batch_create(clients, ACTOR, 3)
    assert len(created) == 3
    assert len(iam_lifecycle.list_pool(clients, "unclaimed")) == 3


def test_claim_happy_path(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)
    item = iam_lifecycle.claim(
        clients, ACTOR, placement_description="leaked in repo", placed_by="tim", environment="prod-honeypot"
    )

    assert item["status"] == "claimed"
    assert item["placement_description"] == "leaked in repo"
    assert item["placed_by"] == "tim"
    assert item["environment"] == "prod-honeypot"
    assert item["claimed_by"] == ACTOR

    tags = {t["Key"]: t["Value"] for t in clients.iam.list_user_tags(UserName=item["iam_username"])["Tags"]}
    assert tags["CostCenter"] == f"CC-{item['batch_id']}"


def test_claim_raises_when_pool_is_empty(clients):
    with pytest.raises(iam_lifecycle.NoUnclaimedCanariesError):
        iam_lifecycle.claim(clients, ACTOR, placement_description="d", placed_by="p", environment="e")


def test_claim_retries_past_contention(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)

    real_update_item = clients.keys_table.update_item
    calls = {"n": 0}

    def flaky_update_item(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _conditional_check_failed()
        return real_update_item(**kwargs)

    clients.keys_table.update_item = flaky_update_item

    item = iam_lifecycle.claim(clients, ACTOR, placement_description="d", placed_by="p", environment="e")

    assert calls["n"] >= 2
    assert item["status"] == "claimed"


def test_purge_unclaimed_dry_run_does_not_delete(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)
    [item] = iam_lifecycle.list_pool(clients, "unclaimed")

    previewed = iam_lifecycle.purge_unclaimed(clients, ACTOR, dry_run=True)

    assert len(previewed) == 1
    # still live in IAM - nothing was actually deleted
    clients.iam.get_user(UserName=item["iam_username"])


def test_purge_unclaimed_execute_deletes_only_unclaimed(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 2)
    [first, second] = iam_lifecycle.list_pool(clients, "unclaimed")
    claimed = iam_lifecycle.claim(
        clients, ACTOR, placement_description="d", placed_by="p", environment="e"
    )
    still_unclaimed = first if first["access_key_id"] != claimed["access_key_id"] else second

    purged = iam_lifecycle.purge_unclaimed(clients, ACTOR, dry_run=False)

    assert [item["access_key_id"] for item in purged] == [still_unclaimed["access_key_id"]]
    with pytest.raises(ClientError):
        clients.iam.get_user(UserName=still_unclaimed["iam_username"])

    # the claimed canary's IAM user and DynamoDB row are both untouched
    clients.iam.get_user(UserName=claimed["iam_username"])
    row = clients.keys_table.get_item(Key={"access_key_id": claimed["access_key_id"]})["Item"]
    assert row["status"] == "claimed"

    purged_row = clients.keys_table.get_item(Key={"access_key_id": still_unclaimed["access_key_id"]})["Item"]
    assert purged_row["status"] == "deleted"
    assert "secret_access_key" not in purged_row


def test_get_canary_detail_merges_events(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    clients.events_table.put_item(
        Item={
            "access_key_id": item["access_key_id"],
            "event_time": "2026-01-01T00:00:00Z#event-1",
            "occurred_at": "2026-01-01T00:00:00Z",
            "event_name": "GetCallerIdentity",
        }
    )

    detail = iam_lifecycle.get_canary_detail(clients, item["access_key_id"])

    assert len(detail["events"]) == 1
    assert detail["events"][0]["event_name"] == "GetCallerIdentity"


def test_get_canary_detail_returns_none_for_unknown_key(clients):
    assert iam_lifecycle.get_canary_detail(clients, "AKIAUNKNOWN") is None
