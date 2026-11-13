"""Identity directory and the Policy Engine's posture/entitlement rules.

Users live in Redis (users:<name> hash) so the directory is persistent and
shared -- the seam where a real OIDC/LDAP connector would plug in. Demo users
are seeded idempotently at startup (and backfilled with new attributes).

Application policy is DATA, not code: the live rules live in the Redis hash
policy:apps (one JSON record per app) and an admin can change them through
the /admin/policy API with no restart (hot reload). APP_TARGETS and
POSTURE_RULES below are only the SEED defaults -- the values a fresh install
starts from. The login flow always reads the live policy via get_policy().
"""
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import redis.asyncio as aioredis

from . import config

_PBKDF2_ROUNDS = 60_000

# Redis keys for policy-as-data. policy:seeded is a marker set once the seed
# has run: without it, an admin deleting every app would look exactly like a
# fresh install and the next login would silently resurrect the defaults.
POLICY_KEY = "policy:apps"
POLICY_SEEDED_KEY = "policy:seeded"

# Per-app session TTL bounds (seconds): shorter than a minute is useless for
# a tunnel, longer than a day defeats the point of an ephemeral micro-tunnel.
SESSION_TTL_MIN_SECONDS = 60
SESSION_TTL_MAX_SECONDS = 86400

# ---------------------------------------------------------------------------
# Protected enterprise applications -- SEED defaults for policy-as-data.
# These constants only define what a fresh install starts with; the live
# policy lives in Redis (see get_policy) and admin edits always win over
# these values, including across restarts.
# ---------------------------------------------------------------------------
APP_TARGETS: Dict[str, str] = {
    "internal-api": "127.0.0.1:8080",
    "metrics-dashboard": "127.0.0.1:9090",
}

# Posture requirements per app. A rule fails only when a claim is present and
# False; with config.POSTURE_STRICT, a missing claim also fails (fail-closed).
POSTURE_RULES: Dict[str, Dict[str, bool]] = {
    "internal-api": {"disk_encrypted": True},
    "metrics-dashboard": {},
}

# Demo directory. In production this table is replaced by the IdP connector;
# the hash format (pbkdf2_sha256$<salt>$<digest>) stays the same.
# `device` is the Common Name of the certificate this identity is registered to
# use. It is what binds a session to a credential instead of a source address:
# a login may only claim the device registered to it, and a PEP running with
# mTLS only honours routes keyed by a verified certificate CN.
_DEMO_USERS: Dict[str, Dict[str, object]] = {
    "alice": {
        "password": "alice-dev-pw", "role": "developer",
        "apps": ["internal-api"], "device": "alice",
    },
    "bob": {
        "password": "bob-analyst-pw", "role": "analyst",
        "apps": ["metrics-dashboard"], "device": "bob",
    },
    "admin": {"password": "admin-console-pw", "role": "admin", "apps": [], "device": ""},
}


# ---------------------------------------------------------------------------
# Policy-as-data: the live rules live in Redis, not in this file.
#
# One record per app, stored as JSON in the policy:apps hash:
#   {"target": "127.0.0.1:8080", "posture": {"disk_encrypted": true},
#    "allowed_hours": "", "session_ttl_seconds": 3600, "enabled": true}
# allowed_hours "" means "always allowed"; otherwise "HH:MM-HH:MM" (24h,
# same-day only). session_ttl_seconds is the route + session lifetime for
# this app -- the JWT lifetime stays the global ACCESS_TOKEN_TTL_SECONDS.
# ---------------------------------------------------------------------------
def default_record(app: str) -> Dict[str, object]:
    """The seed record for one app, built from the constants above."""
    return {
        "target": APP_TARGETS[app],
        "posture": dict(POSTURE_RULES.get(app, {})),
        "allowed_hours": "",
        # The global route TTL is the default, so a fresh install behaves
        # exactly as it did before policy-as-data existed.
        "session_ttl_seconds": config.ROUTE_TTL_SECONDS,
        "enabled": True,
    }


def _seed_policy() -> Dict[str, Dict[str, object]]:
    """The whole seed policy, for callers that have no Redis policy loaded
    (e.g. the demo routes, which still read the constants)."""
    return {app: default_record(app) for app in APP_TARGETS}


async def seed_policy(redis: aioredis.Redis) -> None:
    """Idempotently create the policy hash from the seed defaults.

    HSETNX per app, so an admin edit made before a restart is never
    overwritten by the seed -- the seed only fills in apps that are absent.
    """
    for app in APP_TARGETS:
        await redis.hsetnx(POLICY_KEY, app, json.dumps(default_record(app)))
    await redis.setnx(POLICY_SEEDED_KEY, "1")


# Small in-memory cache so a login storm does not hit Redis for the policy on
# every single login. Admin writes call invalidate_policy_cache(), so a rule
# change is live on the very next login (hot reload); the TTL is only a
# backstop for edits made outside the API.
_policy_cache: Optional[Dict[str, Dict[str, object]]] = None
_policy_cache_at: float = 0.0


def invalidate_policy_cache() -> None:
    """Drop the cached policy; the next get_policy() re-reads Redis."""
    global _policy_cache, _policy_cache_at
    _policy_cache = None
    _policy_cache_at = 0.0


async def get_policy(redis: aioredis.Redis) -> Dict[str, Dict[str, object]]:
    """The live policy: {app name: record}, seeded on first use if absent."""
    global _policy_cache, _policy_cache_at
    now = time.monotonic()
    if _policy_cache is not None and now - _policy_cache_at < config.POLICY_CACHE_SECONDS:
        return _policy_cache
    if not await redis.exists(POLICY_SEEDED_KEY):
        await seed_policy(redis)
    raw = await redis.hgetall(POLICY_KEY)
    policy = {name: json.loads(value) for name, value in raw.items()}
    _policy_cache = policy
    _policy_cache_at = now
    return policy


def policy_now() -> datetime:
    """Local server time, behind one function so tests can monkeypatch the
    clock instead of depending on the real wall time."""
    return datetime.now()


def parse_allowed_hours(value: str) -> Optional[Tuple[datetime, datetime]]:
    """Parse "HH:MM-HH:MM" into (start, end); "" means always allowed (None).

    Raises ValueError on a bad format or an overnight/inverted range: a
    window must fit inside one day (start < end), so "22:00-06:00" is
    rejected rather than silently meaning something surprising.
    """
    value = (value or "").strip()
    if not value:
        return None
    parts = value.split("-", 1)
    if len(parts) != 2:
        raise ValueError("allowed_hours must look like 'HH:MM-HH:MM'")
    try:
        start = datetime.strptime(parts[0].strip(), "%H:%M")
        end = datetime.strptime(parts[1].strip(), "%H:%M")
    except ValueError:
        raise ValueError("allowed_hours must look like 'HH:MM-HH:MM' (24-hour clock)")
    if start >= end:
        raise ValueError("allowed_hours must end after it starts (no overnight ranges)")
    return start, end


def time_window_denial(record: Dict[str, object]) -> Optional[str]:
    """None if this app is usable right now, else a denial message that
    names the window -- so the user knows *when* to come back."""
    try:
        window = parse_allowed_hours(str(record.get("allowed_hours") or ""))
    except ValueError:
        # Stored records are validated on write, so this should not happen;
        # if it does, fail closed instead of crashing the login.
        return "application has a misconfigured access window"
    if window is None:
        return None
    start, end = window
    now = policy_now().time()
    if start.time() <= now < end.time():
        return None
    return "application is only available {}-{} (local server time)".format(
        start.strftime("%H:%M"), end.strftime("%H:%M")
    )


def validate_target(target: str) -> None:
    """'host:port' with a numeric port 1-65535; raises ValueError otherwise."""
    host, sep, port = str(target or "").strip().rpartition(":")
    if not sep or not host:
        raise ValueError("target must look like 'host:port'")
    try:
        port_no = int(port)
    except ValueError:
        raise ValueError("target port must be a number")
    if not 1 <= port_no <= 65535:
        raise ValueError("target port must be between 1 and 65535")


def validate_session_ttl(ttl: int) -> None:
    """Per-app session TTL must fit 60..86400 seconds; ValueError otherwise."""
    if not SESSION_TTL_MIN_SECONDS <= int(ttl) <= SESSION_TTL_MAX_SECONDS:
        raise ValueError(
            "session_ttl_seconds must be between {} and {}".format(
                SESSION_TTL_MIN_SECONDS, SESSION_TTL_MAX_SECONDS
            )
        )


# Usernames and device CNs share one safe alphabet (letters, digits, dot,
# underscore, hyphen, max 64 chars): the same pattern the demo routes use
# for certificate names, so a name can never smuggle a path or key separator
# into a Redis key or a filename.
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# One place builds the directory key, so the PDP can never disagree with
# itself about where a user lives (and the 64-char cap keeps keys bounded).
def user_key(username: str) -> str:
    return "users:{}".format(username[:64])


# Service accounts (machine identities) live under svc:<name> as a hash
# {key_hash, app}. Only the SHA-256 of the API key is stored -- the key
# itself is shown once at creation and can never be read back.
def service_key(name: str) -> str:
    return "svc:{}".format(name[:64])


def hash_api_key(api_key: str) -> str:
    """One-way fingerprint of an API key, for storage and comparison."""
    return hashlib.sha256(api_key.encode()).hexdigest()


# PBKDF2 with a random salt: slow on purpose, so a stolen hash cannot be
# brute-forced cheaply, and salted so identical passwords hash differently.
def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ROUNDS)
    return "pbkdf2_sha256${}${}".format(salt.hex(), digest.hex())


async def seed_users(redis: aioredis.Redis) -> None:
    """Idempotently create the demo directory (never overwrites existing users).

    Uses HSETNX per field so a directory seeded by an earlier version is
    backfilled with newly introduced attributes (e.g. `device`) instead of
    being skipped wholesale.
    """
    for username, spec in _DEMO_USERS.items():
        key = user_key(username)
        fresh = not await redis.exists(key)
        fields = {
            "password_hash": hash_password(str(spec["password"])),
            "role": str(spec["role"]),
            "apps": json.dumps(spec["apps"]),
            "device": str(spec.get("device") or ""),
        }
        if fresh:
            fields["created_at"] = str(int(time.time()))
        for field, value in fields.items():
            await redis.hsetnx(key, field, value)


# A record without a password hash is not a user -- treat a half-written
# directory entry as "no such user" rather than trusting it.
async def get_user(redis: aioredis.Redis, username: str) -> Optional[Dict[str, object]]:
    data = await redis.hgetall(user_key(username))
    if not data or "password_hash" not in data:
        return None
    return {
        "username": username,
        "password_hash": data["password_hash"],
        "role": data.get("role", "user"),
        "apps": json.loads(data.get("apps", "[]")),
        "device": data.get("device", ""),
        # "disabled" is "1" when an admin disabled the account; absent == enabled.
        "disabled": data.get("disabled", "") == "1",
    }


async def verify_credentials(
    redis: aioredis.Redis, username: str, password: str
) -> Optional[Dict[str, object]]:
    """Return the user record on success, None on any failure.

    Comparison is constant-time and unknown users still burn a PBKDF2 round to
    keep response timing uniform between "no such user" and "wrong password".
    """
    user = await get_user(redis, username)
    if user is None:
        _hash_password_dummy(password)
        return None
    salt = bytes.fromhex(str(user["password_hash"]).split("$")[1])
    candidate = hash_password(password, salt)
    if not hmac.compare_digest(candidate, str(user["password_hash"])):
        return None
    # A disabled account fails exactly like a wrong password (same 401, same
    # timing): the caller must never learn whether the account exists.
    if user.get("disabled"):
        return None
    return user


# Burns one PBKDF2 round for an unknown user, so "no such user" takes as
# long as "wrong password" and timing cannot enumerate the directory.
def _hash_password_dummy(password: str) -> None:
    hash_password(password, b"\x00" * 16)


def choose_app(
    user: Dict[str, object],
    requested: Optional[str],
    policy: Optional[Dict[str, Dict[str, object]]] = None,
) -> "str":
    """Resolve the app a login is for; raises PolicyError on entitlement issues.

    `policy` is the live policy from get_policy(); when omitted (the demo
    routes) the seed defaults are used, so those callers behave as before.
    """
    policy = policy if policy is not None else _seed_policy()
    apps: List[str] = list(user.get("apps") or [])
    if requested is None:
        if not apps:
            raise PolicyError("no application entitlement for this identity")
        app = apps[0]
    else:
        if requested not in policy:
            raise PolicyError("unknown application: {}".format(requested))
        if requested not in apps:
            raise PolicyError("not entitled to application: {}".format(requested))
        app = requested
    if app not in policy:
        # The default (first entitled) app was removed from the policy.
        raise PolicyError("unknown application: {}".format(app))
    if not policy[app].get("enabled", True):
        raise PolicyError("application disabled: {}".format(app))
    return app


def registered_device(user: Dict[str, object]) -> str:
    """The certificate CN this identity is registered to ("" if none)."""
    return str(user.get("device") or "").strip()


def device_matches(user: Dict[str, object], device: str) -> bool:
    """True only if `device` is the CN registered to this identity.

    Claiming someone else's certificate identity is what would let one process
    ride another's tunnel, so this is an exact, registered match -- not a
    "any value accepted" field.
    """
    registered = registered_device(user)
    return bool(registered) and hmac.compare_digest(registered, device)


def directory_summary() -> Dict[str, Dict[str, object]]:
    """Role/entitlement view of the directory for the dashboard's attempt panel.

    Deliberately excludes credential material (only role, entitlements and the
    registered device): the UI must predict what a request would be judged on
    without ever seeing why a password verifies.
    """
    return {
        name: {
            "role": str(spec["role"]),
            "apps": list(spec["apps"]),
            "device": str(spec.get("device") or ""),
        }
        for name, spec in _DEMO_USERS.items()
    }


def evaluate_posture(
    app: Optional[str],
    posture: Optional[Dict[str, bool]],
    strict: bool,
    policy: Optional[Dict[str, Dict[str, object]]] = None,
) -> List[str]:
    """Return the list of failed posture rules for this app (empty = pass).

    Rules come from the live policy record when one is passed, else from the
    seed constants (the demo routes). A login with no app (admin console)
    has no rules, so it always passes.
    """
    if policy is None:
        rules = POSTURE_RULES.get(app, {}) if app else {}
    else:
        record = policy.get(app, {}) if app else {}
        rules = record.get("posture", {})
    failures = []
    for claim, required in rules.items():
        value = (posture or {}).get(claim)
        if value is None:
            if strict:
                failures.append("{}: missing".format(claim))
        elif bool(value) != required:
            failures.append("{}: expected {}, got {}".format(claim, required, value))
    return failures


class PolicyError(Exception):
    """Policy-engine denial with a client-safe message."""
