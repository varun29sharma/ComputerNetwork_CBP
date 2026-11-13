"""AegisX Control Plane -- the Policy Decision Point (PDP) of NIST SP 800-207.

Role split inside this process:
  * Policy Engine (PE)         -- /auth/login: identity verification, entitlement
                                 check, device-posture evaluation, JWT minting.
  * Policy Administrator (PA)  -- Lua-atomic route provisioning, session records
                                 (/admin/sessions), revocation (/auth/logout,
                                 /admin/revoke).
  * Policy Information Point (PIP) -- the users:<name> directory in Redis
                                 (stand-in for an OIDC/LDAP IdP; posture claims
                                 stand in for a device-health service).

Identity binding
----------------
A session is authorized by a *binding*: the verified certificate Common Name
("device:alice") when the login asserts a device identity, otherwise the source
address. Only the binding keys routes and sessions, and a login may only assert
the device registered to it -- so a PEP running with mTLS (which authorizes the
certificate CN and nothing else) cannot be ridden by another process on the
same host.
"""
import asyncio
import os
import re
import ssl
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

import jwt as pyjwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse

from . import config, identity, security, state
from .schemas import (
    AdminRevokeRequest,
    AttemptRequest,
    AttemptResponse,
    AttemptStage,
    LoginRequest,
    LoginResponse,
    ProbeRequest,
    ProbeResponse,
    RevocationResponse,
    VerifyResponse,
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
_CERT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = await state.connect()
    await identity.seed_users(app.state.redis)
    yield
    await app.state.redis.aclose()


app = FastAPI(title="AegisX Control Plane", version="0.3.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Auth dependencies (continuous verification on every request)
# ---------------------------------------------------------------------------
async def current_identity(
    request: Request, authorization: Optional[str] = Header(default=None)
) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        claims = security.decode_token(authorization.split(" ", 1)[1].strip())
    except pyjwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    if await state.is_denied(request.app.state.redis, claims["jti"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token revoked")
    return claims


async def require_admin(claims: dict = Depends(current_identity)) -> dict:
    if claims.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return claims


# ---------------------------------------------------------------------------
# Policy Engine + Administrator: login
# ---------------------------------------------------------------------------
@app.post("/auth/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request) -> LoginResponse:
    """Authenticate, evaluate policy, mint a JWT, provision the micro-tunnel.

    Order matters and mirrors the report: identify -> authorize (entitlement +
    device identity + posture) -> only then account for the attempt and write
    the route, so a denied login can never leave a usable tunnel behind.
    """
    redis = request.app.state.redis
    client_ip = body.client_ip or (request.client.host if request.client else None)
    if not client_ip:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot determine client IP")
    posture = body.posture.model_dump() if body.posture else None
    device = (body.device or "").strip() or None

    user = await identity.verify_credentials(redis, body.username, body.password)

    app_name: Optional[str] = None
    if user is not None:
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

        # --- policy engine: entitlements -----------------------------------
        # Admin console identities carry no application entitlement: they can
        # administer sessions but never open a data-plane tunnel.
        if user["role"] == "admin" and body.app is None:
            app_name = None
        else:
            try:
                app_name = identity.choose_app(user, body.app)
            except identity.PolicyError as e:
                await state.audit(
                    redis, "login.app_denied", subject=body.username,
                    client_ip=client_ip, app=body.app, detail=str(e),
                )
                await state.incr_counter(redis, "logins:denied")
                code = (
                    status.HTTP_404_NOT_FOUND
                    if body.app and body.app not in identity.APP_TARGETS
                    else status.HTTP_403_FORBIDDEN
                )
                raise HTTPException(code, str(e))

        failures = identity.evaluate_posture(app_name, posture, config.POSTURE_STRICT)
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

    target = identity.APP_TARGETS.get(app_name) if app_name else None
    binding = state.binding(client_ip, device)

    # Atomic gate: lockout + per-user/per-IP rate limits + route provisioning.
    allowed, _attempts, retry_ms, reason = await state.login_gate(
        redis, body.username, client_ip, target, binding
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
            config.ROUTE_TTL_SECONDS,
        )
    await state.incr_counter(redis, "logins:ok")
    await state.audit(
        redis, "login.success", subject=body.username, client_ip=client_ip,
        app=app_name, role=user["role"], device=device,
    )
    if target:
        await state.audit(
            redis, "tunnel.provisioned", subject=body.username, client_ip=client_ip,
            app=app_name, target=target, ttl=config.ROUTE_TTL_SECONDS,
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


@app.post("/auth/logout", response_model=RevocationResponse)
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


@app.get("/auth/verify", response_model=VerifyResponse)
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


# ---------------------------------------------------------------------------
# Policy Administrator: session visibility and force-revocation
# ---------------------------------------------------------------------------
@app.get("/admin/sessions")
async def admin_sessions(request: Request, claims: dict = Depends(require_admin)) -> List[dict]:
    """Every live tunnel on the gateway, with the identity it is bound to."""
    return await state.list_sessions(request.app.state.redis)


@app.post("/admin/revoke")
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


@app.get("/admin/audit")
async def admin_audit(
    request: Request, limit: int = 50, claims: dict = Depends(require_admin)
) -> List[dict]:
    """Immutable-ish audit trail (Redis Stream) of every allow/deny decision."""
    return await state.recent_audit(request.app.state.redis, max(1, min(limit, 500)))


@app.get("/admin/apps")
async def admin_apps(claims: dict = Depends(require_admin)) -> List[dict]:
    """The policy-as-code view: protected apps and their posture requirements."""
    return [_app_row(name, target) for name, target in identity.APP_TARGETS.items()]


def _app_row(name: str, target: str) -> dict:
    return {
        "name": name,
        "target": target,
        "posture_rules": identity.POSTURE_RULES.get(name, {}),
    }


# ---------------------------------------------------------------------------
# Metrics + real enforcement probe
# ---------------------------------------------------------------------------
@app.get("/metrics")
async def metrics(request: Request) -> dict:
    """Prometheus-friendly counters aggregated from PDP and PEP."""
    data = await state.metrics(request.app.state.redis)
    data["version"] = app.version
    data["pep_probe_addr"] = config.PEP_PROBE_ADDR
    return data


@app.get("/apps")
async def apps() -> List[dict]:
    """Public (demo) description of the protected estate, used by the UI."""
    return [_app_row(name, target) for name, target in identity.APP_TARGETS.items()]


def _cert_paths(name: str) -> tuple:
    """Resolve a device certificate inside the certs directory, or refuse.

    A demo-only endpoint must not become an arbitrary file reader, so the name
    is validated and the resolved paths must stay inside CERTS_DIR.
    """
    if not _CERT_NAME_RE.match(name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid certificate name")
    base = Path(config.CERTS_DIR).resolve()
    crt = (base / "{}.crt".format(name)).resolve()
    key = (base / "{}.key".format(name)).resolve()
    if base not in crt.parents or base not in key.parents:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid certificate name")
    if not (crt.is_file() and key.is_file()):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "no client certificate for '{}'".format(name)
        )
    return str(crt), str(key)


def _cert_common_name(path: str) -> str:
    """Common Name of a PEM certificate (demo helper; no extra dependency)."""
    try:
        decoded = ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined]
        for rdn in decoded.get("subject", ()):
            for field, value in rdn:
                if field == "commonName":
                    return str(value)
    except Exception:
        pass
    return ""


def _available_certs() -> List[str]:
    base = Path(config.CERTS_DIR)
    if not base.is_dir():
        return []
    return sorted(p.stem for p in base.glob("*.crt") if p.stem not in ("ca", "pep"))


@app.post("/demo/probe", response_model=ProbeResponse)
async def demo_probe(body: Optional[ProbeRequest] = None) -> ProbeResponse:
    """Probe the PEP over a REAL TCP socket and report what the gate decided.

    With `cert` set, the connection presents that client certificate, so the
    probe exercises certificate-bound authorization end to end: an unauthorized
    source is cloaked (accepted, then closed with no payload), and a certificate
    with no matching route never reaches an application either.
    """
    addr = (body.addr if body and body.addr else None) or config.PEP_PROBE_ADDR
    return await _run_probe(addr, (body.cert if body and body.cert else ""))


async def _run_probe(addr: str, cert_name: str = "") -> ProbeResponse:
    """Open a real TCP connection to the PEP (optionally with a client
    certificate) and report what came back.

    Shared by /demo/probe and /demo/attempt so the visualization and the probe
    exercise one identical enforcement path rather than two look-alikes.
    """
    host, _, port_s = addr.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "bad probe address")

    ssl_ctx = None
    device = ""
    if cert_name:
        crt, key = _cert_paths(cert_name)
        device = _cert_common_name(crt) or cert_name
        ssl_ctx = ssl.create_default_context(cafile=os.path.join(config.CERTS_DIR, "ca.crt"))
        ssl_ctx.check_hostname = False
        ssl_ctx.load_cert_chain(crt, key)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=3.0
        )
    except ssl.SSLError as e:
        return ProbeResponse(
            allowed=False, reachable=True, addr=addr, tls=bool(ssl_ctx),
            cert=cert_name, device=device, tls_error=True,
            detail="rejected at the TLS handshake: {}".format(str(e)[:120]),
        )
    except OSError as e:
        return ProbeResponse(
            allowed=False, reachable=False, addr=addr, tls=bool(ssl_ctx),
            cert=cert_name, device=device,
            detail="PEP not reachable at {} ({})".format(addr, e.__class__.__name__),
        )
    try:
        writer.write(b"GET /hello HTTP/1.0\r\nHost: probe\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=2.0)
    except (asyncio.TimeoutError, OSError):
        data = b""
    finally:
        writer.close()
    text = data.decode("utf-8", "replace")
    if not data:
        return ProbeResponse(
            allowed=False, reachable=True, addr=addr, tls=bool(ssl_ctx),
            cert=cert_name, device=device,
            detail="connection closed before any payload was read (cloaked)",
        )
    lines = text.splitlines()
    return ProbeResponse(
        allowed=True, reachable=True, addr=addr, tls=bool(ssl_ctx),
        cert=cert_name, device=device, payload=text[:512],
        detail="proxied through the authorized micro-tunnel: {}".format(lines[0] if lines else ""),
    )


def _delivered_port(payload: str) -> int:
    """Which application instance answered: hold-mode banner (`on :8080`) or
    the HTTP target's JSON (`"port": 8080`)."""
    match = re.search(r"on :(\d+)", payload) or re.search(r'"port"\s*:\s*(\d+)', payload)
    return int(match.group(1)) if match else 0


def _app_for_port(port: int) -> str:
    for name, target in identity.APP_TARGETS.items():
        if target.rpartition(":")[2] == str(port):
            return name
    return ""


@app.post("/demo/attempt", response_model=AttemptResponse)
async def demo_attempt(
    body: AttemptRequest, request: Request, claims: dict = Depends(current_identity)
) -> AttemptResponse:
    """Trace one "access that application" attempt, gate by gate, against the
    real system: identity -> entitlement -> authorization record -> data plane.

    The final stage opens an actual TCP connection through the PEP, so the trace
    ends with which application *physically answered* -- not with a prediction.
    It takes no password (the caller is already authenticated and continuously
    verified), so it cannot be used as a rate-limit-free login oracle.
    """
    redis = request.app.state.redis
    binding = claims.get("binding") or claims.get("client_ip", "")
    device = str(claims.get("device") or "")
    identity_name = claims.get("sub", "")
    role = claims.get("role", "")
    requested = body.app
    stages: List[AttemptStage] = []

    stages.append(
        AttemptStage(
            stage="identity", ok=True, title="Identity verified",
            detail="{} · role {} · binding {} (continuously verified)".format(
                identity_name, role, binding or "-"),
        )
    )

    user = await identity.get_user(redis, identity_name)
    entitled = list(user.get("apps") or []) if user else []
    requested_target = identity.APP_TARGETS.get(requested, "")

    # --- gate 1: policy engine (entitlement) ------------------------------
    decision = "ALLOW"
    decided_by = ""
    reason = "identity is entitled to {}".format(requested)
    if user is None:
        decision, decided_by = "DENY", "policy-engine"
        reason = "identity no longer exists in the directory"
    else:
        try:
            app_name = identity.choose_app(user, requested)
        except identity.PolicyError as e:
            decision, decided_by, reason = "DENY", "policy-engine", str(e)
            app_name = ""
    if decision == "ALLOW":
        stages.append(AttemptStage(
            stage="entitlement", ok=True, title="Entitlement check",
            detail="entitled to {} ({})".format(requested, requested_target),
        ))
    else:
        stages.append(AttemptStage(
            stage="entitlement", ok=False, title="Entitlement check", detail=reason,
        ))

    # --- gate 2: authorization record in Redis -----------------------------
    route_key = state.route_key(binding)
    route_target = await redis.get(route_key) or ""
    route_ttl = await redis.ttl(route_key)
    if decision == "ALLOW":
        if not route_target:
            decision, decided_by = "DENY", "gateway"
            reason = "no authorization record: {} is not in Redis".format(route_key)
            stages.append(AttemptStage(
                stage="route", ok=False, title="Authorization record", detail=reason,
            ))
        else:
            stages.append(AttemptStage(
                stage="route", ok=True, title="Authorization record",
                detail="{} = {} ({}s left)".format(route_key, route_target, route_ttl),
            ))
    else:
        stages.append(AttemptStage(
            stage="route", ok=False, title="Authorization record",
            detail="no route was written for this request; live record: {} -> {}".format(
                route_key, route_target or "none"),
        ))

    # --- gate 3: the data plane, over a real socket ------------------------
    gateway: Optional[ProbeResponse] = None
    delivered_port = 0
    delivered_app = ""
    wire = ""
    if decision == "ALLOW":
        probe_addr = (body.addr or "") or config.PEP_PROBE_ADDR
        try:
            gateway = await _run_probe(probe_addr, body.cert or device)
        except HTTPException as e:
            gateway = ProbeResponse(
                allowed=False, reachable=False, addr=probe_addr,
                detail=str(e.detail),
            )
        note = ""
        if not gateway.reachable:
            wire = "unavailable"
            reason = "{} (policy and the authorization record both permit it)".format(gateway.detail)
            stages.append(AttemptStage(
                stage="gateway", ok=False, title="Data plane (real TCP)", detail=reason,
            ))
        elif not gateway.allowed:
            wire = "denied"
            reason = gateway.detail
            # Diagnosis for source-address-bound sessions: the probe originates
            # from this host, so it only traverses a route keyed on this host.
            session_ip = str(claims.get("client_ip") or "")
            if route_target and session_ip and session_ip != "127.0.0.1" and ":" not in route_key:
                reason += (" -- probe originates from 127.0.0.1 while this session is bound "
                           "to {}".format(session_ip))
            stages.append(AttemptStage(
                stage="gateway", ok=False, title="Data plane (real TCP)", detail=reason,
            ))
        else:
            wire = "ok"
            delivered_port = _delivered_port(gateway.payload or gateway.detail)
            delivered_app = _app_for_port(delivered_port)
            detail = "{} answered{}".format(
                ("{} :{}".format(delivered_app, delivered_port)) if delivered_port
                else "the protected application",
                " · certificate {}".format(gateway.cert) if gateway.cert else "")
            if delivered_app and requested_target and delivered_app != requested:
                decision, decided_by = "DENY", "gateway"
                reason = "tunnel delivered {} but {} was requested".format(delivered_app, requested)
                stages.append(AttemptStage(
                    stage="gateway", ok=False, title="Data plane (real TCP)", detail=reason,
                ))
            else:
                stages.append(AttemptStage(
                    stage="gateway", ok=True, title="Data plane (real TCP)", detail=detail,
                ))

    return AttemptResponse(
        identity=identity_name, role=role, binding=binding,
        requested_app=requested, requested_target=requested_target,
        entitled_apps=entitled,
        route_key=route_key, route_target=route_target, route_ttl=max(0, route_ttl),
        decision=decision, decided_by=decided_by, reason=reason, wire=wire,
        stages=stages, gateway=gateway,
        delivered_port=delivered_port, delivered_app=delivered_app,
    )


# ---------------------------------------------------------------------------
# Dashboard + health
# ---------------------------------------------------------------------------
@app.get("/dashboard/state")
async def dashboard_state(request: Request) -> dict:
    """Demo-only live feed (unauthenticated on purpose -- see README security
    notes; production gates this behind admin auth)."""
    redis = request.app.state.redis

    routes: List[dict] = []
    async for key in redis.scan_iter(match="route:*"):
        name = key.split(":", 1)[1]
        parts = state.split_binding(name)
        sess = await redis.hgetall(state.session_key(name))
        routes.append(
            {
                "key": key,
                "identity": name,
                "binding": parts["binding"],
                "device": parts["device"],
                "client_ip": sess.get("client_ip", parts["client_ip"]),
                "user": sess.get("user", ""),
                "target": await redis.get(key),
                "ttl": await redis.ttl(key),
            }
        )

    denylisted: List[dict] = []
    async for key in redis.scan_iter(match="jwt:deny:*"):
        denylisted.append({"key": key, "ttl": await redis.ttl(key)})

    rate_limits: List[dict] = []
    for pattern, prefix, scope in (("login:rl:*", "login:rl:", "user"), ("ipl:*", "ipl:", "ip")):
        async for key in redis.scan_iter(match=pattern):
            rate_limits.append(
                {
                    "key": key,
                    "scope": scope,
                    "username": key[len(prefix):] if scope == "user" else "",
                    "client_ip": key[len(prefix):] if scope == "ip" else "",
                    "attempts": int(await redis.get(key) or 0),
                    "ttl": await redis.ttl(key),
                }
            )

    lockouts: List[dict] = []
    async for key in redis.scan_iter(match="lock:*"):
        lockouts.append(
            {"username": key[len("lock:"):], "ttl": await redis.ttl(key)}
        )

    return {
        "routes": routes,
        "denylisted": denylisted,
        "rate_limits": rate_limits,
        "sessions": await state.list_sessions(redis),
        "lockouts": lockouts,
        "audit": await state.recent_audit(redis, 40),
        "metrics": await state.metrics(redis),
        "apps": [_app_row(name, target) for name, target in identity.APP_TARGETS.items()],
        "users": identity.directory_summary(),
        "certs": _available_certs(),
        "pep_addr": config.PEP_PROBE_ADDR,
        "posture_strict": config.POSTURE_STRICT,
        "route_ttl": config.ROUTE_TTL_SECONDS,
    }


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    page = STATIC_DIR / "index.html"
    if not page.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dashboard asset missing")
    return FileResponse(page, media_type="text/html")


@app.get("/health")
async def health(request: Request) -> Dict[str, str]:
    await request.app.state.redis.ping()
    return {"status": "ok"}
