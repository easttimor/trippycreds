"""Who performed a mutating action - captured server-side, never from a
client-supplied field (that's what `placed_by` is for: a free-text note about
the placement, not an identity claim).

Shape is deliberately caller-agnostic: `{"type": ..., "id": ..., "email": ...}`.
Today there are two sources - a Cognito-authenticated console session, and an
AWS principal for the CLI (via sts:GetCallerIdentity). When a programmatic/API
interface exists, it should populate this same shape (e.g.
`{"type": "api_key", "id": "<key-id>"}`) rather than inventing a parallel field.
"""


class MissingActorError(RuntimeError):
    pass


def from_cognito_claims(claims: dict) -> dict:
    """Built only from the verified JWT claims API Gateway's Cognito authorizer
    attaches to the request (requestContext.authorizer.jwt.claims) - the
    request body is never trusted for this.
    """
    sub = claims.get("sub")
    if not sub:
        raise MissingActorError("authenticated request had no 'sub' claim")
    return {"type": "cognito_user", "id": sub, "email": claims.get("email")}


def from_aws_principal(arn: str) -> dict:
    """Built from sts:GetCallerIdentity - used by the CLI, where there's no
    Cognito session, and later by any SigV4-authenticated programmatic caller.
    """
    return {"type": "aws_principal", "id": arn}
