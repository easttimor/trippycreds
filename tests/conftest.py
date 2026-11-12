"""Shared test fixtures. Everything runs inside a moto mock_aws() context, so
no real AWS credentials or network access are needed - moto intercepts every
boto3 call the real trippycreds.clients.Clients makes, so the library code
under test is exercised unmodified (no monkeypatching of trippycreds itself).
"""

import os

import boto3
import pytest
from moto import mock_aws

from trippycreds.clients import Clients
from trippycreds.config import Config

KEYS_TABLE = "canary-keys"
EVENTS_TABLE = "canary-events"
TRUSTED_PRINCIPALS_TABLE = "trusted-principals"


@pytest.fixture(autouse=True)
def _aws_dummy_credentials(monkeypatch):
    # moto never makes real calls, but boto3/botocore still insist on *some*
    # credentials being present before they'll construct a client.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


@pytest.fixture
def clients():
    with mock_aws():
        _create_tables()
        topic_arn = boto3.client("sns", region_name="us-east-1").create_topic(Name="canary-alerts")[
            "TopicArn"
        ]
        config = Config(
            keys_table_name=KEYS_TABLE,
            events_table_name=EVENTS_TABLE,
            sns_topic_arn=topic_arn,
            trusted_principals_table_name=TRUSTED_PRINCIPALS_TABLE,
            aws_region="us-east-1",
            aws_profile=None,
            managed_by_tag_value="platform-automation",
        )
        yield Clients(config=config)


def _create_tables():
    ddb = boto3.client("dynamodb", region_name="us-east-1")

    ddb.create_table(
        TableName=KEYS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "access_key_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "access_key_id", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-index",
                "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
    )

    ddb.create_table(
        TableName=EVENTS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "access_key_id", "KeyType": "HASH"},
            {"AttributeName": "event_time", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "access_key_id", "AttributeType": "S"},
            {"AttributeName": "event_time", "AttributeType": "S"},
        ],
    )

    ddb.create_table(
        TableName=TRUSTED_PRINCIPALS_TABLE,
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[{"AttributeName": "principal_arn", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "principal_arn", "AttributeType": "S"}],
    )
