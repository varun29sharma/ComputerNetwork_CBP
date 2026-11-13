"""Roadmap 1.1: client_ip comes from the socket, not the payload.

By default a login posting client_ip="198.51.100.7" must NOT get a route bound
to that address -- the route is keyed on the real peer (TestClient connects
as "testclient"). Only with AEGISX_TRUST_PROXY=1 does the proxy's
X-Forwarded-For header win. resolve_client_ip reads the env flag at call
time, so these tests toggle it with monkeypatch -- no app reload needed.
"""
import os
from types import SimpleNamespace

import jwt as pyjwt

from app.routes_auth import resolve_client_ip

TEST_SECRET = os.environ["AEGISX_JWT_SECRET"]

ALICE_PW = "alice-dev-pw"
SPOOFED_IP = "198.51.100.7"
XFF_IP = "203.0.113.55"
ALICE_TARGET = "127.0.0.1:8080"


def fake_request(host="127.0.0.1", headers=None):
    """Minimal stand-in for a Starlette Request: only .client.host and
    .headers.get matter to resolve_client_ip."""
    return SimpleNamespace(
        client=SimpleNamespace(host=host) if host else None,
        headers=headers or {},
    )


def login(client, client_ip=SPOOFED_IP, headers=None):
    return client.post(
        "/auth/login",
        json={"username": "alice", "password": ALICE_PW, "client_ip": client_ip},
        headers=headers or {},
    )


# --- helper unit tests -----------------------------------------------------

def test_helper_trust_off_ignores_payload_and_xff(monkeypatch):
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "0")
    req = fake_request(headers={"x-forwarded-for": XFF_IP})
    assert resolve_client_ip(req, SPOOFED_IP) == "127.0.0.1"


def test_helper_trust_off_no_client_returns_none(monkeypatch):
    # No socket peer and no trusted proxy: the caller (login) must 400.
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "0")
    assert resolve_client_ip(fake_request(host=None), SPOOFED_IP) is None


def test_helper_trust_on_xff_first_entry_wins(monkeypatch):
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "1")
    req = fake_request(headers={"x-forwarded-for": " {} , 10.0.0.1".format(XFF_IP)})
    assert resolve_client_ip(req, SPOOFED_IP) == XFF_IP


def test_helper_trust_on_no_xff_falls_back_to_payload(monkeypatch):
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "1")
    assert resolve_client_ip(fake_request(), SPOOFED_IP) == SPOOFED_IP


def test_helper_trust_on_no_xff_no_payload_uses_socket(monkeypatch):
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "1")
    assert resolve_client_ip(fake_request(), None) == "127.0.0.1"


# --- integration tests (real app + Redis, via the conftest fixtures) -------

def test_login_spoofed_ip_rejected_by_default(client, rdb, monkeypatch):
    """Trust proxy OFF: the payload IP is ignored; the route is bound to the
    TestClient peer ("testclient"), never to 198.51.100.7."""
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "0")
    resp = login(client)
    assert resp.status_code == 200, resp.text
    assert resp.json()["binding"] == "testclient"
    assert resp.json()["route_key"] == "route:testclient"
    assert rdb.get("route:testclient") == ALICE_TARGET
    assert rdb.get("route:{}".format(SPOOFED_IP)) is None
    claims = pyjwt.decode(resp.json()["access_token"], TEST_SECRET, algorithms=["HS256"])
    assert claims["client_ip"] == "testclient"


def test_login_xff_wins_with_trust_proxy(client, rdb, monkeypatch):
    """Trust proxy ON + X-Forwarded-For: the header IP wins over the payload."""
    monkeypatch.setenv("AEGISX_TRUST_PROXY", "1")
    resp = login(client, headers={"X-Forwarded-For": XFF_IP})
    assert resp.status_code == 200, resp.text
    assert resp.json()["binding"] == XFF_IP
    assert resp.json()["route_key"] == "route:{}".format(XFF_IP)
    assert rdb.get("route:{}".format(XFF_IP)) == ALICE_TARGET
    assert rdb.get("route:{}".format(SPOOFED_IP)) is None
