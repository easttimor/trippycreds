from trippycreds import iam_lifecycle, reports

ACTOR = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}

_OLD_TIMESTAMP = "2020-01-01T00:00:00+00:00"


def _backdate(clients, access_key_id, field, value):
    clients.keys_table.update_item(
        Key={"access_key_id": access_key_id},
        UpdateExpression=f"SET {field} = :value",
        ExpressionAttributeValues={":value": value},
    )


def test_stale_claimed_requires_old_claim_and_no_trigger(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)
    item = iam_lifecycle.claim(clients, ACTOR, placement_description="d", placed_by="p", environment="e")
    _backdate(clients, item["access_key_id"], "claimed_at", _OLD_TIMESTAMP)

    report = reports.stale_report(clients, claimed_days=90, unclaimed_days=180)

    assert [row["access_key_id"] for row in report["stale_claimed"]] == [item["access_key_id"]]


def test_claimed_with_recent_trigger_is_not_stale(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)
    item = iam_lifecycle.claim(clients, ACTOR, placement_description="d", placed_by="p", environment="e")
    _backdate(clients, item["access_key_id"], "claimed_at", _OLD_TIMESTAMP)
    _backdate(clients, item["access_key_id"], "last_triggered_at", _OLD_TIMESTAMP)

    report = reports.stale_report(clients, claimed_days=90, unclaimed_days=180)

    assert report["stale_claimed"] == []


def test_recently_claimed_is_not_stale(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)
    iam_lifecycle.claim(clients, ACTOR, placement_description="d", placed_by="p", environment="e")

    report = reports.stale_report(clients, claimed_days=90, unclaimed_days=180)

    assert report["stale_claimed"] == []


def test_aging_unclaimed(clients):
    [item] = iam_lifecycle.batch_create(clients, ACTOR, 1)
    _backdate(clients, item["access_key_id"], "created_at", _OLD_TIMESTAMP)

    report = reports.stale_report(clients, claimed_days=90, unclaimed_days=180)

    assert [row["access_key_id"] for row in report["aging_unclaimed"]] == [item["access_key_id"]]


def test_recently_created_unclaimed_is_not_aging(clients):
    iam_lifecycle.batch_create(clients, ACTOR, 1)

    report = reports.stale_report(clients, claimed_days=90, unclaimed_days=180)

    assert report["aging_unclaimed"] == []
