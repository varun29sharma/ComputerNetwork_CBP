"""Demo routes: metrics, the public app list, the real-TCP probe/attempt
tracer and the dashboard's live state feed. These exist so a demo can show
what the gateway actually did on the wire, not just what policy predicted."""
import asyncio
import os
import re
import ssl
import time
from pathlib import Path
from typing import List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, status

from . import config, identity, state
from .deps import current_identity
from .schemas import (
    AttemptRequest,
    AttemptResponse,
    AttemptStage,
    ProbeRequest,
    ProbeResponse,
)

router = APIRouter()

_CERT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def _app_row(name: str, target: str, posture: Optional[dict] = None) -> dict:
    # One shared shape for the protected-estate listing, used by /apps,
    # /admin/apps and /dashboard/state so the three can never disagree.
    # Callers pass the LIVE policy record's posture; the seed constants are
    # only the fallback for callers that have no policy loaded.
    return {
        "name": name,
        "target": target,
        "posture_rules": posture if posture is not None else identity.POSTURE_RULES.get(name, {}),
    }


# ---------------------------------------------------------------------------
# Metrics + real enforcement probe
# ---------------------------------------------------------------------------
@router.get("/metrics")
async def metrics(request: Request) -> dict:
    """Prometheus-friendly counters aggregated from PDP and PEP."""
    data = await state.metrics(request.app.state.redis)
    data["version"] = request.app.version
    data["pep_probe_addr"] = config.PEP_PROBE_ADDR
    return data


@router.get("/apps")
async def apps(request: Request) -> List[dict]:
    """Public (demo) description of the protected estate, used by the UI.
    Reads the LIVE policy, so an admin PUT is reflected here immediately."""
    policy = await identity.get_policy(request.app.state.redis)
    return [
        _app_row(name, str(record["target"]), dict(record.get("posture") or {}))
        for name, record in policy.items()
    ]


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


@router.post("/demo/probe", response_model=ProbeResponse)
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


def _app_for_port(port: int, policy: dict) -> str:
    """Which app (in the live policy) listens on this port, if any."""
    for name, record in policy.items():
        if str(record.get("target", "")).rpartition(":")[2] == str(port):
            return name
    return ""


@router.post("/demo/attempt", response_model=AttemptResponse)
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
    # The trace judges the LIVE policy, like a real login does -- not the
    # seed defaults, which an admin PUT may have changed since startup.
    policy = await identity.get_policy(redis)
    requested_target = str(policy.get(requested, {}).get("target", ""))

    # --- gate 1: policy engine (entitlement) ------------------------------
    decision = "ALLOW"
    decided_by = ""
    reason = "identity is entitled to {}".format(requested)
    if user is None:
        decision, decided_by = "DENY", "policy-engine"
        reason = "identity no longer exists in the directory"
    else:
        try:
            app_name = identity.choose_app(user, requested, policy)
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
            delivered_app = _app_for_port(delivered_port, policy)
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
# Dashboard
# ---------------------------------------------------------------------------
# How long the dashboard may wait for the PEP to answer a TCP connect. A dead
# PEP must never make the dashboard feed hang -- 0.3s is plenty on localhost
# and bounds the worst case for a remote PEP too.
PEP_PROBE_TIMEOUT_SECONDS = 0.3


async def _pep_reachable() -> Tuple[bool, Optional[float]]:
    """Is the data plane alive, and how fast did it answer the TCP connect?

    A plain connect (no payload): the PEP cloaks unauthorized sources, so
    sending bytes here would prove nothing -- reachability is all the
    dashboard needs. Any failure or timeout means unreachable, never an error.
    """
    host, _, port_s = config.PEP_PROBE_ADDR.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        return False, None
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=PEP_PROBE_TIMEOUT_SECONDS
        )
    except (asyncio.TimeoutError, OSError):
        return False, None
    latency_ms = round((time.monotonic() - started) * 1000, 1)
    writer.close()
    return True, latency_ms


async def _is_admin_request(request: Request) -> bool:
    """True only when the request carries a valid, non-revoked ADMIN token.

    Reuses current_identity -- the same signature/expiry + denylist check
    every protected route uses -- so the dashboard gate can never drift from
    the real auth path. A failure here means "redacted view", not an error,
    so the 401/403 is swallowed and reported as False.
    """
    try:
        claims = await current_identity(request, request.headers.get("authorization"))
    except HTTPException:
        return False
    return claims.get("role") == "admin"


@router.get("/dashboard/state")
async def dashboard_state(request: Request) -> dict:
    """Demo-only live feed. Unauthenticated by default (see README security
    notes); with AEGISX_DASHBOARD_AUTH=1 it shows only the public fields
    unless the request carries a valid admin token -- a 200 redacted view,
    never an error, so the dashboard still loads for anonymous viewers."""
    redis = request.app.state.redis

    # Decide the view first: a redacted request skips the Redis scans for
    # sessions/routes/audit entirely instead of fetching them and throwing
    # them away.
    full_view = not config.DASHBOARD_AUTH or await _is_admin_request(request)
    reachable, latency_ms = await _pep_reachable()
    policy = await identity.get_policy(redis)
    public = {
        "metrics": await state.metrics(redis),
        "apps": [
            _app_row(name, str(record["target"]), dict(record.get("posture") or {}))
            for name, record in policy.items()
        ],
        "pep_reachable": reachable,
        "pep_latency_ms": latency_ms,
        "posture_strict": config.POSTURE_STRICT,
        "route_ttl": config.ROUTE_TTL_SECONDS,
        "certs": _available_certs(),
        "pep_addr": config.PEP_PROBE_ADDR,
    }
    if not full_view:
        return public

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
        **public,
        "routes": routes,
        "denylisted": denylisted,
        "rate_limits": rate_limits,
        "sessions": await state.list_sessions(redis),
        "lockouts": lockouts,
        "audit": await state.recent_audit(redis, 40),
        "users": identity.directory_summary(),
        # The dashboard banner reads this: True while emergency lockdown is on.
        # It lives in the full view, not the public one, so the redacted feed
        # (DASHBOARD_AUTH=1, no admin token) keeps its exact key set.
        "lockdown": await state.is_lockdown(redis),
    }
