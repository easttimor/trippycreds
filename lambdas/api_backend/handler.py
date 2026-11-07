import base64
import json
import logging
from decimal import Decimal

from trippycreds import actor as actor_module
from trippycreds import iam_lifecycle
from trippycreds.clients import Clients

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_clients = None


class BadRequest(ValueError):
    pass


def _get_clients() -> Clients:
    global _clients
    if _clients is None:
        _clients = Clients()
    return _clients


def handler(event, context):
    clients = _get_clients()
    route_key = event.get("routeKey")

    try:
        if route_key == "GET /canaries":
            return _handle_list(clients, event)
        if route_key == "GET /canaries/{access_key_id}":
            return _handle_detail(clients, event)
        if route_key == "POST /canaries/claim":
            return _handle_claim(clients, event)
        if route_key == "POST /canaries/batch-create":
            return _handle_batch_create(clients, event)
        if route_key == "POST /canaries/purge-unclaimed":
            return _handle_purge(clients, event)
        if route_key == "POST /canaries/{access_key_id}/test-trigger":
            return _handle_test_trigger(clients, event)
        return _json_response(404, {"error": f"unknown route: {route_key}"})
    except iam_lifecycle.NoUnclaimedCanariesError as exc:
        return _json_response(409, {"error": str(exc)})
    except iam_lifecycle.IamUserLimitReachedError as exc:
        return _json_response(409, {"error": str(exc)})
    except iam_lifecycle.CanaryNotLiveError as exc:
        return _json_response(409, {"error": str(exc)})
    except actor_module.MissingActorError:
        # Should be unreachable - API Gateway's Cognito authorizer guarantees
        # verified JWT claims on every route below. Surfacing it distinctly
        # (rather than the generic 500) makes an authorizer/config regression
        # obvious instead of looking like an application bug.
        logger.exception("authenticated request had no usable identity claims")
        return _json_response(500, {"error": "internal error: missing authenticated identity"})
    except BadRequest as exc:
        return _json_response(400, {"error": str(exc)})
    except Exception:
        logger.exception("unhandled error processing %s", route_key)
        return _json_response(500, {"error": "internal error"})


def _handle_list(clients: Clients, event: dict) -> dict:
    status = (event.get("queryStringParameters") or {}).get("status", "unclaimed")
    if status not in iam_lifecycle.VALID_STATUSES:
        raise BadRequest(f"status must be one of {iam_lifecycle.VALID_STATUSES}")
    items = [_strip_secret(item) for item in iam_lifecycle.list_pool(clients, status)]
    return _json_response(200, {"items": items})


def _handle_detail(clients: Clients, event: dict) -> dict:
    access_key_id = (event.get("pathParameters") or {}).get("access_key_id")
    if not access_key_id:
        raise BadRequest("access_key_id is required")
    item = iam_lifecycle.get_canary_detail(clients, access_key_id)
    if item is None:
        return _json_response(404, {"error": "no such canary"})
    return _json_response(200, _strip_secret(item))


def _actor_from_event(event: dict) -> dict:
    """The authenticated caller, from the verified JWT claims API Gateway's
    Cognito authorizer attaches to the request - never from the request body.
    """
    claims = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    return actor_module.from_cognito_claims(claims)


def _handle_claim(clients: Clients, event: dict) -> dict:
    body = _parse_body(event)
    placement_description = _require_str(body, "placement_description")
    placed_by = _require_str(body, "placed_by")
    environment = _require_str(body, "environment")
    item = iam_lifecycle.claim(
        clients,
        _actor_from_event(event),
        placement_description=placement_description,
        placed_by=placed_by,
        environment=environment,
    )
    return _json_response(200, item)


def _handle_batch_create(clients: Clients, event: dict) -> dict:
    body = _parse_body(event)
    count = body.get("count")
    if not isinstance(count, int) or count < 1 or count > 100:
        raise BadRequest("count must be an integer between 1 and 100")
    items = [
        _strip_secret(item) for item in iam_lifecycle.batch_create(clients, _actor_from_event(event), count)
    ]
    return _json_response(200, {"items": items})


def _handle_purge(clients: Clients, event: dict) -> dict:
    body = _parse_body(event)
    dry_run = body.get("dry_run", True)
    if not isinstance(dry_run, bool):
        raise BadRequest("dry_run must be a boolean")
    items = iam_lifecycle.purge_unclaimed(clients, _actor_from_event(event), dry_run=dry_run)
    remaining = len(iam_lifecycle.list_pool(clients, "unclaimed")) if not dry_run else 0
    return _json_response(
        200,
        {
            "dry_run": dry_run,
            "items": [_strip_secret(item) for item in items],
            "remaining_unclaimed": remaining,
        },
    )


def _handle_test_trigger(clients: Clients, event: dict) -> dict:
    access_key_id = (event.get("pathParameters") or {}).get("access_key_id")
    if not access_key_id:
        raise BadRequest("access_key_id is required")
    result = iam_lifecycle.trigger_test(clients, _actor_from_event(event), access_key_id)
    if result is None:
        return _json_response(404, {"error": "no such canary"})
    return _json_response(200, result)


def _strip_secret(item: dict) -> dict:
    return {k: v for k, v in item.items() if k != "secret_access_key"}


def _require_str(body: dict, key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BadRequest(f"{key} is required")
    return value


def _parse_body(event: dict) -> dict:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BadRequest("request body must be valid JSON") from exc
    if not isinstance(parsed, dict):
        raise BadRequest("request body must be a JSON object")
    return parsed


def _json_safe(value):
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    return value


def _json_response(status_code: int, payload: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(_json_safe(payload)),
    }
