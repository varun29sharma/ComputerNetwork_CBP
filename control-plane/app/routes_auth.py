"""Auth routes: login (Policy Engine + Administrator), logout, verify,
service-account key exchange."""
import hmac
import os
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from . import config, identity, security, state
from .deps import current_identity
from .schemas import LoginRequest, LoginResponse, RevocationResponse, ServiceAuthRequest, VerifyResponse

router = APIRouter()


def resolve_client_ip(request: Request, body_client_ip: Optional[str]) -> Optional[str]:
    """Decide which source address this login is bound to.

    The payload value is attacker-controlled JSON -- anyone can claim any
    address -- so by default it is ignored and the socket's real peer address
    wins. Only behind a trusted reverse proxy (AEGISX_TRUST_PROXY=1, where the
    proxy itself overwrites X-Forwarded-For) do we believe the header's first
    entry, falling back to the payload value when no header is present (that
    fallback is what lets tests simulate a proxy).
    """
    # Read at call time, not import time, so the flag can be toggled per test
    # without re-importing the app.
    socket_ip = request.client.host if request.client else None
    if os.getenv("AEGISX_TRUST_PROXY", "0") != "1":
        return socket_ip
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded.strip():
        # First entry is the original client; later entries are the proxies
        # the request passed through.
        return forwarded.split(",", 1)[0].strip()
    return body_client_ip or socket_ip


async def _deny_if_lockdown(redis, subject: str, client_ip: str) -> None:
    """Raise 403 when emergency lockdown is on (shared by both login paths:
    a password login and a service-key exchange are both logins, so lockdown
    stops both -- and the audit event is the same either way)."""
    if await state.is_lockdown(redis):
        await state.audit(
            redis, "login.lockdown", subject=subject, client_ip=client_ip,
            detail="logins disabled during emergency lockdown",
        )
        await state.incr_counter(redis, "logins:denied")
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "logins are disabled during an emergency lockdown",
        )


# ---------------------------------------------------------------------------
# Policy Engine + Administrator: login
# ---------------------------------------------------------------------------
@router.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    """Authenticate, evaluate policy, mint a JWT, provision the micro-tunnel.

    Order matters and mirrors the report: identify -> authorize (entitlement +
    device identity + posture) -> only then account for the attempt and write
    the route, so a denied login can never leave a usable tunnel behind.
    """
    redis = request.app.state.redis
    client_ip = resolve_client_ip(request, body.client_ip)
    if not client_ip:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot determine client IP")

    # Emergency lockdown is checked FIRST, before credentials: during an
    # incident nobody logs in, and no attempt is even accounted for.
    await _deny_if_lockdown(redis, body.username, client_ip)

    posture = body.posture.model_dump() if body.posture else None
    device = (body.device or "").strip() or None

    user = await identity.verify_credentials(redis, body.username, body.password)

    # The live policy, loaded once per login so every check below judges the
    # same rules (and so a rule edited a second ago is already in force).
    policy = None
    app_name: Optional[str] = None
    if user is not None:
        policy = await identity.get_policy(redis)

        # --- policy engine: certificate identity registration --------------
        if device and not identity.device_matches(user, device):
            await state.audit(
                redis, "login.device_denied", subject=body.username,
                client_ip=client_ip, device=device,
                detail="certificate identity not registered to this identity",
            )
            await state.incr_counter(redis, "logins:denied")
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "certificate identity '{}' is not registered to this identity".format(device),
            )

        # A revoked certificate is still *registered* (revocation does not
        # erase the registration), so it passes the check above -- and is
        # stopped here, before any route is provisioned.
        if device and await state.is_cert_revoked(redis, device):
            await state.audit(
                redis, "login.device_revoked", subject=body.username,
                client_ip=client_ip, device=device, detail="certificate revoked",
            )
            await state.incr_counter(redis, "logins:denied")
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "certificate '{}' has been revoked".format(device),
            )

        # --- policy engine: entitlements -----------------------------------
        # Admin console identities carry no application entitlement: they can
        # administer sessions but never open a data-plane tunnel.
        if user["role"] == "admin" and body.app is None:
            app_name = None
        else:
            try:
                app_name = identity.choose_app(user, body.app, policy)
            except identity.PolicyError as e:
                await state.audit(
                    redis, "login.app_denied", subject=body.username,
                    client_ip=client_ip, app=body.app, detail=str(e),
                )
                await state.incr_counter(redis, "logins:denied")
                code = (
                    status.HTTP_404_NOT_FOUND
                    if body.app and body.app not in policy
                    else status.HTTP_403_FORBIDDEN
                )
                raise HTTPException(code, str(e))

        failures = identity.evaluate_posture(
            app_name, posture, config.POSTURE_STRICT, policy
        )
        if failures:
            await state.audit(
                redis, "login.posture_denied", subject=body.username,
                client_ip=client_ip, app=app_name, device=device,
                detail="; ".join(failures),
            )
            await state.incr_counter(redis, "logins:denied")
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "device posture denied: {}".format("; ".join(failures)),
            )

        # --- policy engine: time window ------------------------------------
        # Denied before the route is provisioned, like every other policy
        # denial: a login outside the app's hours leaves no tunnel behind.
        if app_name:
            denial = identity.time_window_denial(policy[app_name])
            if denial:
                await state.audit(
                    redis, "login.time_denied", subject=body.username,
                    client_ip=client_ip, app=app_name, device=device, detail=denial,
                )
                await state.incr_counter(redis, "logins:denied")
                raise HTTPException(status.HTTP_403_FORBIDDEN, denial)

    record = policy.get(app_name) if (policy and app_name) else None
    target = str(record["target"]) if record else None
    # The route and session live as long as this app's policy says -- not the
    # global default. The JWT itself is unaffected: its lifetime stays the
    # global ACCESS_TOKEN_TTL_SECONDS, so a short app TTL never shortens the
    # token (and a long one never extends it past exp).
    session_ttl = (
        int(record.get("session_ttl_seconds", config.ROUTE_TTL_SECONDS))
        if record else config.ROUTE_TTL_SECONDS
    )
    binding = state.binding(client_ip, device)

    # Atomic gate: lockout + per-user/per-IP rate limits + route provisioning.
    allowed, _attempts, retry_ms, reason = await state.login_gate(
        redis, body.username, client_ip, target, binding, ttl=session_ttl
    )
    if not allowed:
        await state.audit(
            redis, "login.{}".format(reason), subject=body.username,
            client_ip=client_ip, device=device, detail="retry in {}ms".format(retry_ms),
        )
        await state.incr_counter(redis, "logins:denied")
        retry_after = {"Retry-After": str(max(1, retry_ms // 1000))}
        if reason == "locked":
            raise HTTPException(
                status.HTTP_423_LOCKED,
                "account temporarily locked after repeated failures",
                headers=retry_after,
            )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts", headers=retry_after
        )
    if user is None:
        await state.audit(
            redis, "login.invalid_credentials", subject=body.username, client_ip=client_ip,
        )
        await state.incr_counter(redis, "logins:denied")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    token = security.mint_token(
        body.username, user["role"], client_ip, device=device or "", binding=binding
    )
    claims = security.decode_token(token)

    if target:
        await state.set_session(
            redis,
            binding,
            {
                "user": body.username,
                "role": user["role"],
                "app": app_name or "",
                "target": target,
                "jti": claims["jti"],
                "client_ip": client_ip,
                "device": device or "",
            },
            session_ttl,
        )
    await state.incr_counter(redis, "logins:ok")
    await state.audit(
        redis, "login.success", subject=body.username, client_ip=client_ip,
        app=app_name, role=user["role"], device=device,
    )
    if target:
        await state.audit(
            redis, "tunnel.provisioned", subject=body.username, client_ip=client_ip,
            app=app_name, target=target, ttl=session_ttl,
            device=device, binding=binding,
        )
    return LoginResponse(
        access_token=token,
        expires_in=config.ACCESS_TOKEN_TTL_SECONDS,
        app=app_name or "",
        target=target or "",
        route_key=state.route_key(binding) if target else "",
        posture="pass",
        binding=binding if target else "",
        device=device or "",
    )


# ---------------------------------------------------------------------------
# Service accounts: API-key exchange for machine identities
# ---------------------------------------------------------------------------
@router.post("/auth/service", response_model=LoginResponse)
async def service_login(body: ServiceAuthRequest, request: Request) -> LoginResponse:
    """Exchange a service account's API key for a JWT (role=service).

    No password login: the key is compared by hash (constant-time), and the
    token is good for exactly the one app the account was created for. The
    session gets a route like a normal login, bound to the source address.
    """
    redis = request.app.state.redis
    client_ip = resolve_client_ip(request, None)
    if not client_ip:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot determine client IP")
    await _deny_if_lockdown(redis, body.name, client_ip)

    record = await redis.hgetall(identity.service_key(body.name))
    if not record or not hmac.compare_digest(
        record.get("key_hash", ""), identity.hash_api_key(body.api_key)
    ):
        await state.audit(
            redis, "login.invalid_credentials", subject=body.name, client_ip=client_ip,
        )
        await state.incr_counter(redis, "logins:denied")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid service credentials")

    policy = await identity.get_policy(redis)
    app_name = record.get("app", "")
    app_record = policy.get(app_name)
    if app_record is None or not app_record.get("enabled", True):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "application unavailable: {}".format(app_name)
        )
    denial = identity.time_window_denial(app_record)
    if denial:
        raise HTTPException(status.HTTP_403_FORBIDDEN, denial)

    target = str(app_record["target"])
    session_ttl = int(app_record.get("session_ttl_seconds", config.ROUTE_TTL_SECONDS))
    binding = state.binding(client_ip)
    allowed, _attempts, retry_ms, reason = await state.login_gate(
        redis, "svc:{}".format(body.name), client_ip, target, binding, ttl=session_ttl
    )
    if not allowed:
        retry_after = {"Retry-After": str(max(1, retry_ms // 1000))}
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts", headers=retry_after
        )

    token = security.mint_token(body.name, "service", client_ip, binding=binding)
    claims = security.decode_token(token)
    await state.set_session(
        redis, binding,
        {"user": body.name, "role": "service", "app": app_name, "target": target,
         "jti": claims["jti"], "client_ip": client_ip, "device": ""},
        session_ttl,
    )
    await state.incr_counter(redis, "logins:ok")
    await state.audit(
        redis, "login.success", subject=body.name, client_ip=client_ip,
        app=app_name, role="service",
    )
    return LoginResponse(
        access_token=token,
        expires_in=config.ACCESS_TOKEN_TTL_SECONDS,
        app=app_name,
        target=target,
        route_key=state.route_key(binding),
        posture="pass",
        binding=binding,
        device="",
    )


@router.post("/auth/logout", response_model=RevocationResponse)
async def logout(request: Request, claims: dict = Depends(current_identity)) -> RevocationResponse:
    """Denylist the jti and tear down route + session in one atomic step.

    The route is located by the *binding* recorded in the token, so a
    certificate-bound session is torn down even when the request arrives from a
    different address than the data connection. Already-open tunnels die too:
    the PEP re-validates every live tunnel against Redis on a fixed interval.
    """
    remaining = max(1, int(claims["exp"]) - int(time.time()))
    client_ip = claims.get("client_ip", "")
    binding = claims.get("binding") or client_ip
    await state.revoke(request.app.state.redis, claims["jti"], binding, remaining)
    await state.audit(
        request.app.state.redis, "logout", subject=claims.get("sub"),
        client_ip=client_ip, jti=claims["jti"],
        device=claims.get("device"), binding=binding,
    )
    return RevocationResponse(jti=claims["jti"])


@router.get("/auth/verify", response_model=VerifyResponse)
async def verify(claims: dict = Depends(current_identity)) -> VerifyResponse:
    """Continuous-verification probe: 200 iff the token is valid AND not denied."""
    return VerifyResponse(
        sub=claims["sub"],
        role=claims["role"],
        client_ip=claims.get("client_ip", ""),
        jti=claims["jti"],
        exp=int(claims["exp"]),
        device=claims.get("device", ""),
        binding=claims.get("binding") or claims.get("client_ip", ""),
    )
