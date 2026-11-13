"""Test fixtures. Requires a reachable Redis (AEGISX_REDIS_URL, default local).

The suite clears only AegisX-namespaced keys before each test so it never
clobbers unrelated data in a shared instance. Every namespace the app writes is
listed below -- missing one leaks state between tests (notably lock:*, which
would 423 later logins).
"""
import os

os.environ.setdefault("AEGISX_REDIS_URL", "redis://127.0.0.1:6379")
os.environ.setdefault("AEGISX_JWT_SECRET", "test-secret-0123456789abcdef0123456789abcdef")
# Tests log in with a client_ip in the JSON body while TestClient connects
# from "testclient": that only works with the trusted-proxy fallback on, so
# the suite simulates a trusted proxy by default (test_trust_proxy.py covers
# the default-off behaviour explicitly with monkeypatch).
os.environ.setdefault("AEGISX_TRUST_PROXY", "1")

import pytest
import redis as sync_redis
from fastapi.testclient import TestClient

from app.main import app

KEY_PREFIXES = (
    "route:",
    "sess:",
    "jwt:deny:",
    "login:rl:",
    "ipl:",
    "fails:",
    "lock:",
)
KEY_EXACT = (
    "audit:events",
    "pep:allow",
    "pep:deny",
    "pep:closed",
    "pep:active",
    "logins:ok",
    "logins:denied",
    "admin:revocations",
)


@pytest.fixture(scope="session")
def rdb():
    client = sync_redis.from_url(os.environ["AEGISX_REDIS_URL"], decode_responses=True)
    yield client
    client.close()


@pytest.fixture()
def client(rdb):
    for prefix in KEY_PREFIXES:
        for key in rdb.scan_iter(match=prefix + "*"):
            rdb.delete(key)
    if KEY_EXACT:
        rdb.delete(*KEY_EXACT)
    with TestClient(app) as c:
        yield c
