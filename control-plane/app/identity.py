"""Identity directory and the Policy Engine's posture/entitlement rules.

Users live in Redis (users:<name> hash) so the directory is persistent and
shared -- the seam where a real OIDC/LDAP connector would plug in. Demo users
are seeded idempotently at startup (and backfilled with new attributes).
APP_TARGETS, POSTURE_RULES and the per-identity `device` registration are the
policy-as-code configuration the Policy Engine evaluates on every login.
"""
import hashlib
import hmac
import json
import os
import time
from typing import Dict, List, Optional

import redis.asyncio as aioredis

_PBKDF2_ROUNDS = 60_000

# ---------------------------------------------------------------------------
# Protected enterprise applications (policy-as-code).
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


def user_key(username: str) -> str:
    return "users:{}".format(username[:64])


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
    return user


def _hash_password_dummy(password: str) -> None:
    hash_password(password, b"\x00" * 16)


def choose_app(user: Dict[str, object], requested: Optional[str]) -> "str":
    """Resolve the app a login is for; raises PolicyError on entitlement issues."""
    apps: List[str] = list(user.get("apps") or [])
    if requested is None:
        if not apps:
            raise PolicyError("no application entitlement for this identity")
        return apps[0]
    if requested not in APP_TARGETS:
        raise PolicyError("unknown application: {}".format(requested))
    if requested not in apps:
        raise PolicyError("not entitled to application: {}".format(requested))
    return requested


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


def evaluate_posture(app: str, posture: Optional[Dict[str, bool]], strict: bool) -> List[str]:
    """Return the list of failed posture rules for this app (empty = pass)."""
    rules = POSTURE_RULES.get(app, {})
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
