import logging

from trippycreds.clients import Clients
from trippycreds.events import process_cloudtrail_record

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_clients = None


def _get_clients() -> Clients:
    global _clients
    if _clients is None:
        _clients = Clients()
    return _clients


def handler(event, context):
    """Triggered directly by EventBridge's built-in CloudTrail integration
    ('AWS API Call via CloudTrail') - no trail required. Each invocation
    carries exactly one CloudTrail record, under event['detail'].
    """
    clients = _get_clients()
    record = event.get("detail")
    if not record:
        logger.warning("event had no 'detail', skipping: %s", event)
        return {"matched": False}

    matched = process_cloudtrail_record(clients, record)
    logger.info(
        "processed 1 record (eventName=%s), matched a tracked canary: %s",
        record.get("eventName"),
        matched,
    )
    return {"matched": matched}
