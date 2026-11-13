"""Admin policy endpoints: policy-as-data CRUD over the policy:apps hash.

Every write invalidates the in-memory policy cache, so the next login is
judged by the new rules with no restart (hot reload). Every write is also
audited, so the audit stream shows who changed which app's rules and when.
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Request, status

from . import config, identity, state
from .deps import require_admin
from .schemas import PolicyListResponse, PolicyRecord, PolicyUpdate

router = APIRouter()


def _as_422(message: str) -> HTTPException:
    # A bad rule is the caller's fault, not a server error: 422, like a
    # Pydantic validation failure, with a message that says what is wrong.
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, message)


@router.get("/admin/policy", response_model=PolicyListResponse)
async def list_policy(
    request: Request, _claims: dict = Depends(require_admin)
) -> PolicyListResponse:
    """The whole live policy, keyed by application name."""
    policy = await identity.get_policy(request.app.state.redis)
    return PolicyListResponse(
        apps={name: PolicyRecord(**record) for name, record in policy.items()}
    )


@router.put("/admin/policy/{app}", response_model=PolicyRecord)
async def upsert_policy(
    app: str, body: PolicyUpdate, request: Request,
    claims: dict = Depends(require_admin),
) -> PolicyRecord:
    """Create or update one app's policy record (hot reload: live on the
    next login). Fields not sent keep their current value; `target` is
    required when creating an app that does not exist yet."""
    redis = request.app.state.redis
    policy = await identity.get_policy(redis)
    existing = policy.get(app)
    if existing is None and body.target is None:
        raise _as_422("target is required when creating a new application")

    # Start from the current record (or the defaults for a new app) and
    # overlay only the fields the caller sent.
    record: dict = dict(existing) if existing is not None else {
        "target": "",
        "posture": {},
        "allowed_hours": "",
        "session_ttl_seconds": config.ROUTE_TTL_SECONDS,
        "enabled": True,
    }
    if body.target is not None:
        record["target"] = body.target
    if body.posture is not None:
        record["posture"] = body.posture
    if body.allowed_hours is not None:
        record["allowed_hours"] = body.allowed_hours
    if body.session_ttl_seconds is not None:
        record["session_ttl_seconds"] = body.session_ttl_seconds
    if body.enabled is not None:
        record["enabled"] = body.enabled

    # Validate the merged record, not just the sent fields, so a partial
    # update can never leave a broken record behind.
    try:
        identity.validate_target(str(record["target"]))
        identity.parse_allowed_hours(str(record["allowed_hours"]))
        identity.validate_session_ttl(int(record["session_ttl_seconds"]))
    except ValueError as e:
        raise _as_422(str(e))

    await redis.hset(identity.POLICY_KEY, app, json.dumps(record))
    identity.invalidate_policy_cache()
    await state.audit(
        redis, "policy.updated", subject=claims.get("sub"), app=app,
        target=record["target"],
    )
    return PolicyRecord(**record)


@router.delete("/admin/policy/{app}")
async def delete_policy(
    app: str, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Remove an app from the policy. A later login for it is denied as an
    unknown application; the seed never brings it back (see policy:seeded)."""
    redis = request.app.state.redis
    policy = await identity.get_policy(redis)
    if app not in policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown application: {}".format(app))
    await redis.hdel(identity.POLICY_KEY, app)
    identity.invalidate_policy_cache()
    await state.audit(redis, "policy.deleted", subject=claims.get("sub"), app=app)
    return {"status": "deleted", "app": app}
