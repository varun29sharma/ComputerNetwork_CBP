"""Admin routes: session visibility, force-revocation, audit, policy view,
device enrollment + revocation, user management, lockouts, lockdown, audit
export and service accounts. Every route requires the admin role, and every
action is written to the audit stream (who did what, to whom, when)."""
import csv
import io
import json
import secrets
import time
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response

from . import identity, state
from .deps import require_admin
from .routes_demo import _CERT_NAME_RE, _app_row
from .schemas import (
    AdminRevokeRequest,
    CreateUserRequest,
    DeviceRegisterRequest,
    DeviceRevokeRequest,
    LockdownRequest,
    ServiceAccountRequest,
    UnlockRequest,
    UserResponse,
)

router = APIRouter()

# The only roles the directory knows. Anything else is a caller error (422),
# not a new role -- inventing roles by typo would silently break require_admin.
USER_ROLES = ("developer", "analyst", "admin")

# Audit-export columns. The stream stores the timestamp as `ts`; the export
# renames it to `timestamp` so the CSV reads naturally.
EXPORT_FIELDS = ("timestamp", "event", "subject", "client_ip", "app", "detail")


async def _revoke_sessions(redis, **match) -> int:
    """Revoke every live session whose record matches all given fields.

    With no fields it revokes everything (the lockdown path). Matching is done
    on the PDP's session records, and each session goes through the same
    revoke path as /admin/revoke, so open tunnels die at the next PEP
    revalidation.
    """
    revoked = 0
    for sess in await state.list_sessions(redis):
        if all(sess.get(key) == value for key, value in match.items()):
            if await state.revoke_binding(redis, str(sess["identity"])):
                revoked += 1
    return revoked


def _as_422(message: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, message)


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


@router.get("/admin/audit/export")
async def admin_audit_export(
    request: Request, format: str = "json", limit: int = 500,
    claims: dict = Depends(require_admin),
) -> Response:
    """Download the audit trail as JSON (default) or CSV, for offline review."""
    if format not in ("json", "csv"):
        raise _as_422("format must be 'json' or 'csv'")
    events = await state.recent_audit(request.app.state.redis, max(1, min(limit, 500)))
    await state.audit(request.app.state.redis, "admin.audit_export", subject=claims.get("sub"))
    if format == "json":
        return Response(
            content=json.dumps(events),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="aegisx-audit.json"'},
        )
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(EXPORT_FIELDS))
    writer.writeheader()
    for event in events:
        # The stream stores `ts`; the export calls it `timestamp`.
        writer.writerow({field: event.get("ts" if field == "timestamp" else field, "")
                         for field in EXPORT_FIELDS})
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="aegisx-audit.csv"'},
    )


@router.get("/admin/apps")
async def admin_apps(request: Request, claims: dict = Depends(require_admin)) -> List[dict]:
    """The protected apps and their posture requirements, from the LIVE policy
    (so an admin PUT shows up here immediately, not just at the next login)."""
    policy = await identity.get_policy(request.app.state.redis)
    return [
        _app_row(name, str(record["target"]), dict(record.get("posture") or {}))
        for name, record in policy.items()
    ]


# ---------------------------------------------------------------------------
# Device enrollment + certificate revocation
# ---------------------------------------------------------------------------
@router.post("/admin/devices")
async def register_device(
    body: DeviceRegisterRequest, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Register a device (certificate CN) to an existing user.

    The CN is what the login binds to: afterwards the user may assert this
    device, and only this device. The name is validated with the same pattern
    the demo routes use for certificate names, so it can never smuggle a path
    or key separator into Redis or the certs directory.
    """
    redis = request.app.state.redis
    device = body.device.strip()
    if not _CERT_NAME_RE.match(device):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid device name")
    if await identity.get_user(redis, body.username) is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "unknown user: {}".format(body.username)
        )
    await redis.hset(identity.user_key(body.username), "device", device)
    await state.audit(
        redis, "admin.device_registered", subject=claims.get("sub"),
        target=body.username, device=device,
    )
    return {"username": body.username, "device": device}


@router.post("/admin/devices/revoke")
async def revoke_device(
    body: DeviceRevokeRequest, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Revoke a device certificate: deny future logins AND kill live sessions.

    The deny key alone only blocks *new* tunnels (the PEP checks it at
    tunnel-open time), so every live session bound to this CN is also revoked
    through the normal revoke path -- open tunnels then die at the next PEP
    revalidation instead of surviving until their TTL.
    """
    redis = request.app.state.redis
    device = body.device.strip()
    if not _CERT_NAME_RE.match(device):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid device name")
    await state.revoke_cert(redis, device)
    revoked = await _revoke_sessions(redis, device=device)
    await state.audit(
        redis, "admin.device_revoked", subject=claims.get("sub"), device=device,
        detail="{} live session(s) revoked".format(revoked),
    )
    await state.incr_counter(redis, "admin:revocations")
    return {"status": "revoked", "device": device, "sessions_revoked": revoked}


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
@router.post("/admin/users", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
async def create_user(
    body: CreateUserRequest, request: Request, claims: dict = Depends(require_admin)
) -> UserResponse:
    """Create a directory user (passwords are PBKDF2-hashed, never stored)."""
    redis = request.app.state.redis
    username = body.username.strip()
    if not identity.USERNAME_RE.match(username):
        raise _as_422("username may only use letters, digits, '.', '_' and '-'")
    if body.role not in USER_ROLES:
        raise _as_422("role must be one of: {}".format(", ".join(USER_ROLES)))
    device = (body.device or "").strip()
    if device and not _CERT_NAME_RE.match(device):
        raise _as_422("invalid device name")
    if await redis.exists(identity.user_key(username)):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "user already exists: {}".format(username)
        )
    # Entitlements must name apps the live policy knows, or the user could
    # never log in to them (choose_app would deny them as unknown).
    policy = await identity.get_policy(redis)
    unknown = [app for app in body.apps if app not in policy]
    if unknown:
        raise _as_422("unknown application: {}".format(unknown[0]))
    await redis.hset(
        identity.user_key(username),
        mapping={
            "password_hash": identity.hash_password(body.password),
            "role": body.role,
            "apps": json.dumps(list(body.apps)),
            "device": device,
            "created_at": str(int(time.time())),
        },
    )
    await state.audit(
        redis, "admin.user_created", subject=claims.get("sub"), target=username,
        role=body.role,
    )
    return UserResponse(username=username, role=body.role, apps=list(body.apps), device=device)


@router.post("/admin/users/{name}/disable")
async def disable_user(
    name: str, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Disable an account AND revoke its live sessions (same 401 as a bad
    password afterwards, so a disabled account is indistinguishable from a
    wrong password to anyone probing the login)."""
    redis = request.app.state.redis
    if await identity.get_user(redis, name) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown user: {}".format(name))
    await redis.hset(identity.user_key(name), "disabled", "1")
    revoked = await _revoke_sessions(redis, user=name)
    await state.audit(
        redis, "admin.user_disabled", subject=claims.get("sub"), target=name,
        detail="{} live session(s) revoked".format(revoked),
    )
    return {"username": name, "disabled": True, "sessions_revoked": revoked}


@router.post("/admin/users/{name}/enable")
async def enable_user(
    name: str, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Re-enable a disabled account (the flag is deleted, not set to "0",
    so a fresh account and a re-enabled one look identical in Redis)."""
    redis = request.app.state.redis
    if await identity.get_user(redis, name) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown user: {}".format(name))
    await redis.hdel(identity.user_key(name), "disabled")
    await state.audit(redis, "admin.user_enabled", subject=claims.get("sub"), target=name)
    return {"username": name, "disabled": False}


# ---------------------------------------------------------------------------
# Lockout management
# ---------------------------------------------------------------------------
@router.get("/admin/lockouts")
async def list_lockouts(request: Request, claims: dict = Depends(require_admin)) -> dict:
    """Who is locked out right now, and for how long.

    `users` are truly locked out (lock:* keys after repeated failures; the
    value is the remaining seconds until the lock expires).
    `rate_limited_ips` are source IPs currently inside a per-IP rate-limit
    window (ipl:* keys) -- NOT locked out, just windowed. An ipl:* key is
    created on any login attempt, so most entries here are ordinary logins.
    """
    redis = request.app.state.redis
    users = []
    async for key in redis.scan_iter(match="lock:*"):
        users.append(
            {"username": key[len("lock:"):], "remaining_seconds": max(0, await redis.ttl(key))}
        )
    rate_limited_ips = []
    async for key in redis.scan_iter(match="ipl:*"):
        rate_limited_ips.append(
            {"ip": key[len("ipl:"):], "remaining_seconds": max(0, await redis.ttl(key))}
        )
    return {"users": users, "rate_limited_ips": rate_limited_ips}


@router.post("/admin/unlock")
async def unlock(
    body: UnlockRequest, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Clear a lockout: the failure streak and the lock for a user, and/or
    the rate-limit window for an IP. At least one of the two must be given."""
    if not (body.username or "").strip() and not (body.ip or "").strip():
        raise _as_422("give a username, an ip, or both")
    redis = request.app.state.redis
    username = (body.username or "").strip() or None
    ip = (body.ip or "").strip() or None
    if username:
        await redis.delete(state.fails_key(username), state.lock_key(username))
    if ip:
        await redis.delete(state.ip_rate_key(ip))
    await state.audit(
        redis, "admin.unlock", subject=claims.get("sub"), target=username, client_ip=ip,
    )
    return {"status": "unlocked", "username": username, "ip": ip}


# ---------------------------------------------------------------------------
# Emergency lockdown
# ---------------------------------------------------------------------------
@router.post("/admin/lockdown")
async def set_lockdown(
    body: LockdownRequest, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Switch emergency lockdown on or off. Turning it ON also revokes every
    live session, so open tunnels die within one PEP revalidation interval
    instead of lingering until their TTL."""
    redis = request.app.state.redis
    await state.set_lockdown(redis, body.on)
    revoked = await _revoke_sessions(redis) if body.on else 0
    await state.audit(
        redis, "admin.lockdown", subject=claims.get("sub"),
        detail="lockdown {}".format("on" if body.on else "off"),
    )
    return {"lockdown": body.on, "sessions_revoked": revoked}


@router.get("/admin/lockdown")
async def get_lockdown(request: Request, claims: dict = Depends(require_admin)) -> dict:
    """Is emergency lockdown on right now?"""
    return {"lockdown": await state.is_lockdown(request.app.state.redis)}


# ---------------------------------------------------------------------------
# Service accounts (machine identities)
# ---------------------------------------------------------------------------
@router.post("/admin/service-accounts", status_code=status.HTTP_201_CREATED)
async def create_service_account(
    body: ServiceAccountRequest, request: Request, claims: dict = Depends(require_admin)
) -> dict:
    """Create a service account for one app. The API key is shown ONCE, in
    this response -- only its SHA-256 hash is stored, so it can never be
    read back (a leaked database does not leak usable keys)."""
    redis = request.app.state.redis
    name = body.name.strip()
    if not identity.USERNAME_RE.match(name):
        raise _as_422("name may only use letters, digits, '.', '_' and '-'")
    if await redis.exists(identity.service_key(name)):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "service account already exists: {}".format(name)
        )
    policy = await identity.get_policy(redis)
    if body.app not in policy:
        raise _as_422("unknown application: {}".format(body.app))
    api_key = secrets.token_urlsafe(32)
    await redis.hset(
        identity.service_key(name),
        mapping={"key_hash": identity.hash_api_key(api_key), "app": body.app},
    )
    await state.audit(
        redis, "admin.service_account_created", subject=claims.get("sub"),
        target=name, app=body.app,
    )
    return {"name": name, "app": body.app, "api_key": api_key}
