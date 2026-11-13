"""Control-plane tests: login provisioning, revocation, cloaking preconditions."""
import os
import time

import jwt as pyjwt
import pytest

TEST_SECRET = os.environ["AEGISX_JWT_SECRET"]

ALICE_PW = "alice-dev-pw"
CLIENT_IP = "203.0.113.10"
ALICE_TARGET = "127.0.0.1:8080"


def login(client, username="alice", password=ALICE_PW, client_ip=CLIENT_IP):
    return client.post(
        "/auth/login", json={"username": username, "password": password, "client_ip": client_ip}
    )


def bearer(client, token):
    return {"Authorization": "Bearer {}".format(token)}


def test_login_success_provisions_route(client, rdb):
    resp = login(client)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target"] == ALICE_TARGET
    assert body["route_key"] == "route:{}".format(CLIENT_IP)

    # The PEP's sole source of truth: route:<client_ip> -> micro-tunnel target.
    assert rdb.get("route:{}".format(CLIENT_IP)) == ALICE_TARGET
    ttl = rdb.ttl("route:{}".format(CLIENT_IP))
    assert 0 < ttl <= 3600

    claims = pyjwt.decode(body["access_token"], TEST_SECRET, algorithms=["HS256"])
    assert claims["sub"] == "alice"
    assert claims["role"] == "developer"
    assert claims["client_ip"] == CLIENT_IP
    assert claims["jti"]


def test_login_bad_password_401_and_no_route(client, rdb):
    resp = login(client, password="wrong")
    assert resp.status_code == 401
    assert rdb.get("route:{}".format(CLIENT_IP)) is None


def test_login_unknown_user_401(client, rdb):
    resp = login(client, username="mallory", password="whatever")
    assert resp.status_code == 401
    assert rdb.get("route:{}".format(CLIENT_IP)) is None


def test_rate_limit_429_after_burst(client, rdb):
    for _ in range(5):
        assert login(client).status_code == 200
    resp = login(client)
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
    # The limiter also throttles brute-force bursts of bad passwords.
    for _ in range(3):
        assert login(client, password="nope").status_code == 429


def test_verify_requires_token(client):
    assert client.get("/auth/verify").status_code == 401
    assert client.get("/auth/verify", headers=bearer(client, "garbage")).status_code == 401


def test_forged_signature_401(client):
    forged = pyjwt.encode(
        {"sub": "alice", "role": "admin", "client_ip": CLIENT_IP, "jti": "x",
         "iat": int(time.time()), "exp": int(time.time()) + 600},
        "attacker-secret-that-is-long-enough-000000",
        algorithm="HS256",
    )
    assert client.get("/auth/verify", headers=bearer(client, forged)).status_code == 401


def test_logout_revokes_token_and_route(client, rdb):
    token = login(client).json()["access_token"]

    # Session is live: continuous verification passes.
    assert client.get("/auth/verify", headers=bearer(client, token)).status_code == 200
    assert rdb.get("route:{}".format(CLIENT_IP)) == ALICE_TARGET

    logout = client.post("/auth/logout", headers=bearer(client, token))
    assert logout.status_code == 200
    jti = logout.json()["jti"]

    # Token is cryptographically valid until exp, but the denylist wins.
    assert client.get("/auth/verify", headers=bearer(client, token)).status_code == 401
    # PEP's authorization proof is gone immediately -- cloaking restored.
    assert rdb.get("route:{}".format(CLIENT_IP)) is None
    # Denylist entry self-expires with the token's remaining lifetime.
    assert rdb.exists("jwt:deny:{}".format(jti)) == 1
    assert 0 < rdb.ttl("jwt:deny:{}".format(jti)) <= 3600


def test_logout_requires_valid_token(client):
    assert client.post("/auth/logout").status_code == 401


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}
