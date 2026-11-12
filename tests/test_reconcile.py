import json

from trippycreds import iam_lifecycle, reconcile

ACTOR = {"type": "aws_principal", "id": "arn:aws:iam::123456789012:user/operator"}


def _findings_by_username(report, username):
    return [f for f in report["findings"] if f["iam_username"] == username]


def _finding_types(report, username):
    return {f["type"] for f in _findings_by_username(report, username)}


def test_consistent_canary_has_no_findings(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)

    report = reconcile.run(clients)

    assert _findings_by_username(report, item["iam_username"]) == []


def test_orphan_in_iam(clients):
    clients.iam.create_user(UserName="orphan-user", Tags=[{"Key": "ManagedBy", "Value": "platform-automation"}])

    report = reconcile.run(clients)

    assert _finding_types(report, "orphan-user") == {"orphan_in_iam"}


def test_untagged_canary_user(clients):
    clients.iam.create_user(UserName="untagged-user")

    report = reconcile.run(clients)

    # no tag at all -> both "nobody claims to know about this" and "it's not
    # even tagged as a canary" are true at once
    assert _finding_types(report, "untagged-user") == {"orphan_in_iam", "untagged_canary_user"}


def test_zombie_deleted(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    clients.keys_table.update_item(
        Key={"access_key_id": item["access_key_id"]},
        UpdateExpression="SET #status = :deleted REMOVE secret_access_key",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":deleted": "deleted"},
    )

    report = reconcile.run(clients)

    assert _finding_types(report, item["iam_username"]) == {"zombie_deleted"}


def test_missing_in_iam(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    username = item["iam_username"]
    clients.iam.delete_access_key(UserName=username, AccessKeyId=item["access_key_id"])
    clients.iam.delete_user_policy(UserName=username, PolicyName="canary-deny-all-except-recon")
    clients.iam.delete_user(UserName=username)

    report = reconcile.run(clients)

    assert _finding_types(report, username) == {"missing_in_iam"}


def test_tag_mismatch(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    clients.iam.tag_user(UserName=item["iam_username"], Tags=[{"Key": "CostCenter", "Value": "CC-9999"}])

    report = reconcile.run(clients)

    assert _finding_types(report, item["iam_username"]) == {"tag_mismatch"}


def test_quarantined(clients):
    item = iam_lifecycle.create_canary(clients, ACTOR)
    policy_arn = clients.iam.create_policy(
        PolicyName="AWSCompromisedKeyQuarantineV2",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
        ),
    )["Policy"]["Arn"]
    clients.iam.attach_user_policy(UserName=item["iam_username"], PolicyArn=policy_arn)

    report = reconcile.run(clients)

    [finding] = _findings_by_username(report, item["iam_username"])
    assert finding["type"] == "quarantined"
    assert "AWSCompromisedKeyQuarantineV2" in finding["detail"]


def test_notify_publishes_only_when_findings_exist(clients):
    assert reconcile.notify(clients, {"findings": []}) is None  # no-op, must not raise

    clients.iam.create_user(UserName="orphan-user", Tags=[{"Key": "ManagedBy", "Value": "platform-automation"}])
    report = reconcile.run(clients)
    reconcile.notify(clients, report)  # must not raise
