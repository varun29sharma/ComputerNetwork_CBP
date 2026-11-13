"""Admin routes: session visibility, force-revocation, audit, policy view."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from . import identity, state
from .deps import require_admin
from .routes_demo import _app_row
from .schemas import AdminRevokeRequest

router = APIRouter()


@router.get("/admin/sessions")
async def admin_sessions(request: Request, claims: dict = Depends(require_admin)) -> List[dict]:
    """Every live tunnel on the gateway, with the identity it is bound to."""
    return await state.list_sessions(request.app.state.redis)


@router.post("/admin/revoke")
async def admin_revoke(
    body: AdminRevokeRequest, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Force-revoke a live tunnel (SOC response to an incident).

    Identify the session by certificate identity (preferred) or source address.
    The admin does not need the victim's token: the PDP looks up the session
    record, denylists its jti for its remaining lifetime, and deletes the route
    and session keys, so the PEP and the PDP agree instantly.
    """
    redis = request.app.state.redis
    device = (body.device or "").strip()
    if device:
        binding = state.binding(body.client_ip or "", device)
    elif body.client_ip:
        binding = state.binding(body.client_ip, None)
    else:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "identify the session by device or client_ip"
        )

    sess = await redis.hgetall(state.session_key(binding))
    if not sess:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "no live session for that device or client IP"
        )
    jti = sess.get("jti", "")
    remaining = max(1, await redis.ttl(state.route_key(binding)))
    await state.revoke(redis, jti, binding, remaining)
    await state.audit(
        redis, "admin.revoke", subject=claims.get("sub"), binding=binding,
        client_ip=sess.get("client_ip", body.client_ip or ""), device=device or sess.get("device"),
        target=sess.get("user", "unknown"), jti=jti, reason=body.reason or "",
    )
    await state.incr_counter(redis, "admin:revocations")
    return {
        "status": "revoked",
        "binding": binding,
        "client_ip": sess.get("client_ip", body.client_ip or ""),
        "device": device or sess.get("device", ""),
        "revoked_user": sess.get("user", "unknown"),
        "jti": jti,
    }


@router.get("/admin/audit")
async def admin_audit(
    request: Request, limit: int = 50, claims: dict = Depends(require_admin)
) -> List[dict]:
    """Immutable-ish audit trail (Redis Stream) of every allow/deny decision."""
    return await state.recent_audit(request.app.state.redis, max(1, min(limit, 500)))


@router.get("/admin/apps")
async def admin_apps(claims: dict = Depends(require_admin)) -> List[dict]:
    """The policy-as-code view: protected apps and their posture requirements."""
    return [_app_row(name, target) for name, target in identity.APP_TARGETS.items()]
