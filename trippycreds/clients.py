from typing import Optional

import boto3

from .config import Config


class Clients:
    """Bundles the boto3 clients/tables the lifecycle and event-processing code needs."""

    def __init__(self, config: Optional[Config] = None, session: Optional[boto3.Session] = None):
        self.config = config or Config.from_env()
        self.session = session or boto3.Session(
            profile_name=self.config.aws_profile,
            region_name=self.config.aws_region,
        )
        self.iam = self.session.client("iam")
        self.sns = self.session.client("sns")
        self.sts = self.session.client("sts")
        dynamodb = self.session.resource("dynamodb")
        self.keys_table = dynamodb.Table(self.config.keys_table_name)
        self.events_table = dynamodb.Table(self.config.events_table_name)
        # None for event_consumer (see Config.trusted_principals_table_name) -
        # boto3's Table() validates its name argument eagerly, so it can't be
        # constructed with None the way the other two tables are above.
        self.trusted_principals_table = (
            dynamodb.Table(self.config.trusted_principals_table_name)
            if self.config.trusted_principals_table_name
            else None
        )
