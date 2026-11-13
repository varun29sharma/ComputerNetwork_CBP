"""Redis state store: the high-speed broker between PDP (Python) and PEP (Java).

Key schema
----------
route:<binding>     -> "host:port" of the single authorized micro-tunnel (TTL).
                       <binding> is "device:<cert CN>" for certificate-bound
                       sessions (what a PEP running mTLS consults) or the source
                       address for plaintext sessions.
sess:<binding>      -> hash {user, role, app, target, jti, client_ip, device}
                       -- the PDP's view of the live session; same TTL as the route.
jwt:deny:<jti>      -> denylist entry for a revoked token (TTL == remaining exp).
login:rl:<u>        -> per-user login rate window.
ipl:<client_ip>     -> per-source-IP login rate window.
fails:<u>           -> consecutive failed logins (drives lockout).
lock:<u>            -> account locked after LOGIN_FAIL_MAX consecutive failures.
audit:events        -> Redis Stream: every allow/deny/login/logout/admin action.
pep:allow|deny|active|closed -> data-plane counters (written by the Netty PEP).
policy:apps         -> hash {app name: JSON policy record} (policy-as-data).
policy:seeded       -> marker set once the seed policy has been written.
cert:deny:<CN>      -> revoked device certificate (24h TTL; see revoke_cert).
admin:lockdown      -> "1" while emergency lockdown is on (absent == off).
svc:<name>          -> service-account hash {key_hash, app}.
"""
import time
from typing import Dict, List, Optional

import redis.asyncio as aioredis

from . import config

# Atomic login gate: lockout check + per-user and per-IP rate accounting +
# failure-streak tracking + micro-tunnel provisioning, in one indivisible op.
# Atomicity matters because check-then-write in separate commands races: two
# concurrent logins could both pass the rate check before either increments
# (doubling the allowed burst), or a failed login could slip a route in
# between the policy check and the write. Inside one Lua script Redis runs
# the whole gate with no other command interleaved, so that cannot happen.
# KEYS[1]=user rl  KEYS[2]=route (keyed by session binding)  KEYS[3]=ip rl
# KEYS[4]=fails  KEYS[5]=lock
# ARGV[1]=win ARGV[2]=max_user ARGV[3]=target('') ARGV[4]=route_ttl
# ARGV[5]=ip_win ARGV[6]=ip_max ARGV[7]=fail_max ARGV[8]=lock_ttl
# -> {allowed, n, retry_ms, reason}  reason: locked|ratelimit|fail|ok
LOGIN_LUA = """
if redis.call('EXISTS', KEYS[5]) == 1 then
  return {-2, 0, redis.call('PTTL', KEYS[5]), 'locked'}
end
local u = redis.call('INCR', KEYS[1])
if u == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
local i = redis.call('INCR', KEYS[3])
if i == 1 then redis.call('EXPIRE', KEYS[3], ARGV[5]) end
local u_retry = redis.call('PTTL', KEYS[1])
if tonumber(u) > tonumber(ARGV[2]) or tonumber(i) > tonumber(ARGV[6]) then
  return {0, u, u_retry, 'ratelimit'}
end
if ARGV[3] == '' then
  local f = redis.call('INCR', KEYS[4])
  if f == 1 then redis.call('EXPIRE', KEYS[4], ARGV[8]) end
  if tonumber(f) >= tonumber(ARGV[7]) then
    redis.call('SET', KEYS[5], '1', 'EX', ARGV[8])
    return {-2, f, redis.call('PTTL', KEYS[5]), 'locked'}
  end
  return {1, f, u_retry, 'fail'}
end
redis.call('DEL', KEYS[4])
redis.call('SET', KEYS[2], ARGV[3], 'EX', tonumber(ARGV[4]))
return {1, u, u_retry, 'ok'}
"""

# Atomic revocation: denylist the jti, delete the PEP's route and the PDP's
# session record in one operation -- the PEP can never see a half-revoked
# session, and continuous revalidation kills already-open tunnels.
# Without atomicity a crash (or a concurrent revalidation read) between the
# denylist write and the route delete would leave the tunnel live while the
# token looks revoked, or vice versa -- the two planes would disagree.
# KEYS[1]=denylist KEYS[2]=route KEYS[3]=sess  ARGV[1]=deny ttl
LOGOUT_LUA = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('SET', KEYS[1], '1', 'EX', tonumber(ARGV[1]))
end
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[3])
return 1
"""


DEVICE_PREFIX = "device:"


def binding(client_ip: str, device: Optional[str] = None) -> str:
    """The identity a session is authorized by.

    With a verified certificate it is the certificate Common Name
    ("device:alice"); otherwise it degrades to the source address. Only the
    binding -- never the raw client IP -- is used to key routes and sessions,
    so a certificate-bound session cannot be reached from the same host under a
    different credential.
    """
    device = (device or "").strip()
    return "{}{}".format(DEVICE_PREFIX, device) if device else client_ip


def split_binding(name: str) -> Dict[str, str]:
    """Decompose a route/session suffix into device and client-IP parts."""
    if name.startswith(DEVICE_PREFIX):
        return {"binding": "device", "device": name[len(DEVICE_PREFIX):], "client_ip": ""}
    return {"binding": "ip", "device": "", "client_ip": name}


# Key builders: one place builds each Redis key name, so the PDP (and the
# Java PEP, which hard-codes the same prefixes) can never disagree on a name.
def route_key(binding_name: str) -> str:
    return "route:{}".format(binding_name)


def session_key(binding_name: str) -> str:
    return "sess:{}".format(binding_name)


def denylist_key(jti: str) -> str:
    return "jwt:deny:{}".format(jti)


def rate_limit_key(username: str) -> str:
    return "login:rl:{}".format(username[:64])


def ip_rate_key(client_ip: str) -> str:
    return "ipl:{}".format(client_ip)


def fails_key(username: str) -> str:
    return "fails:{}".format(username[:64])


def lock_key(username: str) -> str:
    return "lock:{}".format(username[:64])


# Emergency lockdown flag: the key exists ("1") while lockdown is on and is
# deleted when it is switched off, so "absent" always means "normal".
LOCKDOWN_KEY = "admin:lockdown"

# A revoked certificate stays denied for 24h. That is a demo TTL, not a real
# CRL: a production deployment needs a persistent revocation list, because a
# 24h entry expires and the certificate would work again after it.
CERT_DENY_TTL_SECONDS = 86400


def cert_deny_key(device: str) -> str:
    return "cert:deny:{}".format(device)


async def is_lockdown(redis: aioredis.Redis) -> bool:
    return bool(await redis.exists(LOCKDOWN_KEY))


async def set_lockdown(redis: aioredis.Redis, on: bool) -> None:
    if on:
        await redis.set(LOCKDOWN_KEY, "1")
    else:
        await redis.delete(LOCKDOWN_KEY)


async def revoke_cert(redis: aioredis.Redis, device: str) -> None:
    """Deny one certificate CN (the PEP checks this key at tunnel-open time)."""
    await redis.set(cert_deny_key(device), "1", ex=CERT_DENY_TTL_SECONDS)


async def is_cert_revoked(redis: aioredis.Redis, device: str) -> bool:
    return bool(await redis.exists(cert_deny_key(device)))


# decode_responses=True: keys and values come back as str, not bytes, so
# the rest of the code never has to decode Redis replies by hand.
async def connect() -> aioredis.Redis:
    return aioredis.from_url(config.REDIS_URL, decode_responses=True)


# ---------------------------------------------------------------------------
# Audit trail (Redis Stream)
# ---------------------------------------------------------------------------
async def audit(redis: aioredis.Redis, event: str, **fields) -> None:
    """Append one event to the audit stream (fire-and-forget safe)."""
    body: Dict[str, str] = {"event": event, "ts": str(int(time.time()))}
    body.update({k: str(v) for k, v in fields.items() if v is not None})
    await redis.xadd("audit:events", body, maxlen=10000, approximate=True)


# Newest-first (xrevrange): the dashboard and /admin/audit want the latest
# decisions, not the oldest ones.
async def recent_audit(redis: aioredis.Redis, count: int = 50) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    raw = await redis.xrevrange("audit:events", count=count)
    for entry_id, fields in raw:
        row = dict(fields)
        row["id"] = entry_id
        entries.append(row)
    return entries


# ---------------------------------------------------------------------------
# Session records (PDP view of a live tunnel)
# ---------------------------------------------------------------------------
# Written as one pipeline so the session record and its TTL land together:
# a record without a TTL would outlive its route and look live forever.
async def set_session(
    redis: aioredis.Redis, binding_name: str, mapping: Dict[str, str], ttl: int
) -> None:
    pipe = redis.pipeline()
    pipe.hset(session_key(binding_name), mapping=mapping)
    pipe.expire(session_key(binding_name), ttl)
    await pipe.execute()


async def list_sessions(redis: aioredis.Redis) -> List[Dict[str, object]]:
    """Every live tunnel, with the identity it is bound to."""
    sessions: List[Dict[str, object]] = []
    async for key in redis.scan_iter(match="route:*"):
        name = key.split(":", 1)[1]
        parts = split_binding(name)
        sess = await redis.hgetall(session_key(name))
        sessions.append(
            {
                "identity": name,
                # "device" when the tunnel is certificate-bound, else "ip".
                "binding": parts["binding"],
                "device": parts["device"],
                "client_ip": sess.get("client_ip", parts["client_ip"]),
                "target": await redis.get(key),
                "ttl": await redis.ttl(key),
                "user": sess.get("user", "unknown"),
                "role": sess.get("role", ""),
                "app": sess.get("app", ""),
                "jti": sess.get("jti", ""),
            }
        )
    return sessions


# ---------------------------------------------------------------------------
# Login gate / revocation
# ---------------------------------------------------------------------------
async def login_gate(
    redis: aioredis.Redis, username: str, client_ip: str, target: str,
    binding_name: Optional[str] = None, ttl: Optional[int] = None,
):
    """Atomically account for this login attempt and provision the route.

    Returns (allowed, attempts, retry_after_ms, reason). The route (KEYS[2]) is
    keyed by the session's binding -- "device:<cert CN>" for certificate-bound
    sessions, otherwise the source address. `ttl` is the route lifetime: the
    app's session_ttl_seconds when the login is for an app, else the global
    ROUTE_TTL_SECONDS default.
    """
    result = await redis.eval(
        LOGIN_LUA,
        5,
        rate_limit_key(username),
        route_key(binding_name or client_ip),
        ip_rate_key(client_ip),
        fails_key(username),
        lock_key(username),
        str(config.RATE_LIMIT_WINDOW_SECONDS),
        str(config.RATE_LIMIT_MAX_ATTEMPTS),
        target or "",
        str(ttl if ttl is not None else config.ROUTE_TTL_SECONDS),
        str(config.RATE_LIMIT_WINDOW_SECONDS),
        str(config.RATE_LIMIT_IP_MAX_ATTEMPTS),
        str(config.LOGIN_FAIL_MAX),
        str(config.LOCKOUT_SECONDS),
    )
    allowed, attempts, retry_ms, reason = result
    return int(allowed) == 1, int(attempts), int(retry_ms), str(reason)


async def revoke(redis: aioredis.Redis, jti: str, binding_name: str, remaining_ttl: int) -> None:
    """Denylist the token for its remaining lifetime + drop route and session."""
    await redis.eval(
        LOGOUT_LUA,
        3,
        denylist_key(jti),
        route_key(binding_name),
        session_key(binding_name),
        str(max(1, remaining_ttl)),
    )


async def revoke_binding(redis: aioredis.Redis, binding_name: str) -> bool:
    """Revoke one live session by its binding (the admin bulk-revoke path).

    Looks the session record up itself, so callers that only know a device or
    a username never need the victim's token. A route with no session record
    (no jti to denylist) still has its keys deleted. Returns True when
    anything was actually revoked.
    """
    sess = await redis.hgetall(session_key(binding_name))
    route_exists = await redis.exists(route_key(binding_name))
    if not sess and not route_exists:
        return False
    jti = sess.get("jti", "")
    if jti:
        remaining = max(1, await redis.ttl(route_key(binding_name)))
        await revoke(redis, jti, binding_name, remaining)
    else:
        await redis.delete(route_key(binding_name), session_key(binding_name))
    return True


async def is_denied(redis: aioredis.Redis, jti: str) -> bool:
    """Continuous-verification check: is this jti on the denylist?"""
    return bool(await redis.exists(denylist_key(jti)))


# ---------------------------------------------------------------------------
# Counters (metrics)
# ---------------------------------------------------------------------------
# Redis INCR is atomic, so concurrent logins cannot lose a count.
async def incr_counter(redis: aioredis.Redis, name: str) -> None:
    await redis.incr(name)


# One pipeline read for all counters, plus a live count of route:* keys, so
# /metrics shows the PDP and PEP views from (nearly) the same moment.
async def metrics(redis: aioredis.Redis) -> Dict[str, int]:
    names = ("pep:allow", "pep:deny", "pep:closed", "pep:revoked",
             "logins:ok", "logins:denied", "admin:revocations")
    pipe = redis.pipeline()
    for name in names:
        pipe.get(name)
    values = await pipe.execute()
    counts = {name: int(value or 0) for name, value in zip(names, values)}
    active = await redis.get("pep:active")
    session_count = 0
    async for _ in redis.scan_iter(match="route:*"):
        session_count += 1
    return {
        "pep_allow_total": counts["pep:allow"],
        "pep_deny_total": counts["pep:deny"],
        "pep_closed_total": counts["pep:closed"],
        "pep_revoked_total": counts["pep:revoked"],
        "logins_ok_total": counts["logins:ok"],
        "logins_denied_total": counts["logins:denied"],
        "admin_revocations_total": counts["admin:revocations"],
        "pep_active_tunnels": int(active or 0),
        "active_sessions": session_count,
    }
