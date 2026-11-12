import logging

from trippycreds import reconcile
from trippycreds.clients import Clients

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_clients = None


def _get_clients() -> Clients:
    global _clients
    if _clients is None:
        _clients = Clients()
    return _clients


def handler(event, context):
    """Triggered on a schedule (see terraform/lambda_reconciler.tf) to diff
    live IAM state against DynamoDB and flag AWS-side key quarantines - see
    trippycreds/reconcile.py for what's actually being checked.
    """
    clients = _get_clients()
    report = reconcile.run(clients)
    if report["findings"]:
        reconcile.notify(clients, report)
    logger.info(
        "reconciliation complete: checked %d IAM user(s) / %d DynamoDB row(s), %d finding(s)",
        report["iam_user_count"],
        report["ddb_row_count"],
        len(report["findings"]),
    )
    return {"finding_count": len(report["findings"])}
