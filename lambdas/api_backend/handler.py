import base64
import json
import logging
from decimal import Decimal

from trippycreds import actor as actor_module
from trippycreds import bake
from trippycreds import iam_lifecycle
from trippycreds import reconcile
from trippycreds import reports
from trippycreds import trusted_principals
from trippycreds.clients import Clients

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_clients = None


class BadRequest(ValueError):
    pass


class Forbidden(ValueError):
    pass


def _get_clients() -> Clients:
    global _clients
    if _clients is None:
        _clients = Clients()
    return _clients


def handler(event, context):
    clients = _get_clients()
    # The HTTP API (console/registry routes, Cognito-authorized) sends
    # `routeKey`. The REST API (the cross-account service-claim route,
    # AWS_IAM-authorized - see terraform/rest_api_service.tf) uses the older
    # v1 proxy event shape instead, with no `routeKey` at all - reconstruct
    # the same "METHOD /path" form from it so one dispatch table covers both.
    route_key = event.get("routeKey") or f"{event.get('httpMethod')} {event.get('resource')}"

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
        if route_key == "GET /trusted-principals":
            return _handle_list_trusted_principals(clients, event)
        if route_key == "POST /trusted-principals":
            return _handle_register_trusted_principal(clients, event)
        if route_key == "POST /trusted-principals/disable":
            return _handle_disable_trusted_principal(clients, event)
        if route_key == "POST /service/claim":
            return _handle_service_claim(clients, event)
        if route_key == "POST /reconcile":
            return _handle_reconcile(clients, event)
        if route_key == "GET /reports/stale":
            return _handle_stale_report(clients, event)
        return _json_response(404, {"error": f"unknown route: {route_key}"})
    except iam_lifecycle.NoUnclaimedCanariesError as exc:
        return _json_response(409, {"error": str(exc)})
    except iam_lifecycle.IamUserLimitReachedError as exc:
        return _json_response(409, {"error": str(exc)})
    except iam_lifecycle.CanaryNotLiveError as exc:
        return _json_response(409, {"error": str(exc)})
    except actor_module.MissingActorError:
        # Should be unreachable - every route above is behind either API
        # Gateway's Cognito authorizer (verified JWT claims) or its native
        # AWS_IAM authorizer (verified SigV4 caller identity). Surfacing this
        # distinctly (rather than the generic 500) makes an authorizer/config
        # regression obvious instead of looking like an application bug.
        logger.exception("authenticated request had no usable identity claims")
        return _json_response(500, {"error": "internal error: missing authenticated identity"})
    except Forbidden as exc:
        return _json_response(403, {"error": str(exc)})
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
    """The authenticated console/CLI-via-API caller, from the verified JWT
    claims API Gateway's Cognito authorizer attaches to the request - never
    from the request body.
    """
    claims = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    return actor_module.from_cognito_claims(claims)


def _caller_arn_from_iam_auth(event: dict) -> str:
    """The authenticated service-API caller's ARN, from API Gateway's native
    AWS_IAM authorizer (which already verified the request's SigV4 signature)
    - never from the request body. Only the REST API's AWS_IAM-authorized
    route (POST /service/claim) populates this.
    """
    arn = event.get("requestContext", {}).get("identity", {}).get("userArn")
    if not arn:
        raise actor_module.MissingActorError("AWS_IAM-authorized request had no caller identity")
    return arn


def _apply_format(body: dict, item: dict) -> dict:
    """Optional, additive: `format` asks for the claimed credentials also
    rendered as a paste-ready leaked-file snippet (see trippycreds/bake.py).
    Omitted entirely, the response shape is identical to before this existed.
    """
    fmt = body.get("format")
    if not fmt:
        return item
    if fmt not in bake.FORMATS:
        raise BadRequest(f"format must be one of {bake.FORMATS}")
    item = dict(item)
    item["baked_snippet"] = bake.render(item, fmt)
    return item


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
    return _json_response(200, _apply_format(body, item))


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


def _handle_list_trusted_principals(clients: Clients, event: dict) -> dict:
    return _json_response(200, {"items": trusted_principals.list_principals(clients)})


def _handle_register_trusted_principal(clients: Clients, event: dict) -> dict:
    body = _parse_body(event)
    principal_arn = _require_str(body, "principal_arn")
    label = _require_str(body, "label")
    environment = body.get("environment") or None
    allowed_actions = body.get("allowed_actions") or list(trusted_principals.DEFAULT_ALLOWED_ACTIONS)
    if not isinstance(allowed_actions, list) or not all(isinstance(a, str) for a in allowed_actions):
        raise BadRequest("allowed_actions must be a list of strings")
    item = trusted_principals.register(
        clients,
        _actor_from_event(event),
        principal_arn=principal_arn,
        label=label,
        allowed_actions=allowed_actions,
        environment=environment,
    )
    return _json_response(200, item)


def _handle_disable_trusted_principal(clients: Clients, event: dict) -> dict:
    body = _parse_body(event)
    principal_arn = _require_str(body, "principal_arn")
    item = trusted_principals.disable(clients, _actor_from_event(event), principal_arn)
    if item is None:
        return _json_response(404, {"error": "no such trusted principal"})
    return _json_response(200, item)


def _handle_service_claim(clients: Clients, event: dict) -> dict:
    """Cross-account, no-operator-in-the-loop claim - see
    trippycreds/trusted_principals.py and DESIGN.md's "Cross-account service
    claims" section. Reached only via the separate REST API's AWS_IAM-
    authorized POST /service/claim route, never the console's HTTP API.
    """
    caller_arn = _caller_arn_from_iam_auth(event)
    registry_item = trusted_principals.is_authorized(clients, caller_arn, action="claim")
    if registry_item is None:
        raise Forbidden(f"{caller_arn} is not a trusted principal for 'claim'")

    body = _parse_body(event)
    placement_description = _require_str(body, "placement_description")
    environment = _require_str(body, "environment")
    allowed_environment = registry_item.get("environment")
    if allowed_environment and allowed_environment != environment:
        raise Forbidden(
            f"{registry_item['principal_arn']} is only trusted to claim in environment "
            f"'{allowed_environment}', not '{environment}'"
        )
    placed_by = body.get("placed_by") or registry_item.get("label") or caller_arn

    item = iam_lifecycle.claim(
        clients,
        actor_module.from_aws_principal(caller_arn),
        placement_description=placement_description,
        placed_by=placed_by,
        environment=environment,
    )
    return _json_response(200, _apply_format(body, item))


def _handle_reconcile(clients: Clients, event: dict) -> dict:
    """On-demand version of the scheduled reconciler Lambda (see
    lambdas/reconciler/handler.py) - same trippycreds/reconcile.py logic,
    triggered from the console instead of a schedule.
    """
    report = reconcile.run(clients)
    if report["findings"]:
        reconcile.notify(clients, report)
    return _json_response(200, report)


def _handle_stale_report(clients: Clients, event: dict) -> dict:
    params = event.get("queryStringParameters") or {}
    try:
        claimed_days = int(params.get("claimed_days", reports.DEFAULT_CLAIMED_STALE_DAYS))
        unclaimed_days = int(params.get("unclaimed_days", reports.DEFAULT_UNCLAIMED_AGING_DAYS))
    except ValueError as exc:
        raise BadRequest("claimed_days/unclaimed_days must be integers") from exc
    report = reports.stale_report(clients, claimed_days=claimed_days, unclaimed_days=unclaimed_days)
    return _json_response(200, report)


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
