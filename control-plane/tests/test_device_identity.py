"""Certificate-identity binding: a session keyed by the certificate CN, not the IP.

This is the property that stops two processes on one host from sharing a
tunnel: the route a PEP running with mTLS consults is `route:device:<CN>`, and a
login can only assert the device registered to it.
"""
import os
import socket
import threading
from pathlib import Path

import jwt as pyjwt
import pytest

TEST_SECRET = os.environ["AEGISX_JWT_SECRET"]
CLIENT_IP = "203.0.113.40"
ALICE_TARGET = "127.0.0.1:8080"


def login(client, username="alice", password="alice-dev-pw", client_ip=CLIENT_IP, **extra):
    payload = {"username": username, "password": password, "client_ip": client_ip}
    payload.update(extra)
    return client.post("/auth/login", json=payload)


def bearer(token):
    return {"Authorization": "Bearer {}".format(token)}


def admin_token(client):
    resp = login(client, "admin", "admin-console-pw", "203.0.113.41")
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------
def test_device_login_keys_the_route_by_certificate_identity(client, rdb):
    resp = login(client, device="alice")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # The PEP (mTLS) only ever reads the device key...
    assert rdb.get("route:device:alice") == ALICE_TARGET
    assert 0 < rdb.ttl("route:device:alice") <= 3600
    # ...and nothing was written under the source address, so a different
    # process on this host has no route to find.
    assert rdb.get("route:{}".format(CLIENT_IP)) is None

    assert body["binding"] == "device:alice"
    assert body["device"] == "alice"
    assert body["route_key"] == "route:device:alice"

    claims = pyjwt.decode(body["access_token"], TEST_SECRET, algorithms=["HS256"])
    assert claims["device"] == "alice"
    assert claims["binding"] == "device:alice"
    assert claims["client_ip"] == CLIENT_IP


def test_claiming_another_identitys_certificate_is_denied(client, rdb):
    # alice may not assert bob's certificate identity (which would let her ride
    # bob's tunnel / reach bob's app).
    resp = login(client, device="bob")
    assert resp.status_code == 403
    assert "not registered" in resp.json()["detail"]
    assert rdb.get("route:device:bob") is None
    assert rdb.get("route:device:alice") is None
    assert rdb.get("route:{}".format(CLIENT_IP)) is None


def test_unregistered_device_identity_is_denied(client, rdb):
    assert login(client, device="total-stranger").status_code == 403
    assert rdb.get("route:device:total-stranger") is None


def test_login_without_a_device_stays_source_address_bound(client, rdb):
    # Backwards compatible: the plaintext path is unchanged.
    body = login(client).json()
    assert body["binding"] == CLIENT_IP
    assert body["device"] == ""
    assert rdb.get("route:{}".format(CLIENT_IP)) == ALICE_TARGET
    assert rdb.get("route:device:alice") is None


def test_blank_device_falls_back_to_source_address(client, rdb):
    assert login(client, device="   ").status_code == 200
    assert rdb.get("route:{}".format(CLIENT_IP)) == ALICE_TARGET


# ---------------------------------------------------------------------------
# Revocation follows the binding
# ---------------------------------------------------------------------------
def test_logout_tears_down_the_device_route(client, rdb):
    token = login(client, device="alice").json()["access_token"]
    assert rdb.get("route:device:alice") == ALICE_TARGET

    resp = client.post("/auth/logout", headers=bearer(token))
    assert resp.status_code == 200
    jti = resp.json()["jti"]

    assert rdb.get("route:device:alice") is None
    assert rdb.exists("jwt:deny:{}".format(jti)) == 1
    assert rdb.hgetall("sess:device:alice") == {}
    assert client.get("/auth/verify", headers=bearer(token)).status_code == 401


def test_verify_reports_the_binding(client):
    token = login(client, device="alice").json()["access_token"]
    body = client.get("/auth/verify", headers=bearer(token)).json()
    assert body["binding"] == "device:alice"
    assert body["device"] == "alice"


# ---------------------------------------------------------------------------
# Visibility
# ---------------------------------------------------------------------------
def test_sessions_expose_the_certificate_identity(client):
    login(client, device="alice")
    sessions = client.get("/admin/sessions", headers=bearer(admin_token(client))).json()
    entry = next(s for s in sessions if s["identity"] == "device:alice")
    assert entry["binding"] == "device"
    assert entry["device"] == "alice"
    assert entry["client_ip"] == CLIENT_IP  # audit address, not the auth key
    assert entry["user"] == "alice"
    assert entry["target"] == ALICE_TARGET


def test_dashboard_state_shows_the_device_route(client):
    login(client, device="alice")
    body = client.get("/dashboard/state").json()
    route = next(r for r in body["routes"] if r["identity"] == "device:alice")
    assert route["device"] == "alice"
    assert route["binding"] == "device"
    assert route["client_ip"] == CLIENT_IP
    assert route["target"] == ALICE_TARGET


def test_admin_revoke_by_certificate_identity(client, rdb):
    victim = login(client, device="alice").json()["access_token"]
    hdr = bearer(admin_token(client))

    resp = client.post(
        "/admin/revoke", json={"device": "alice", "reason": "stolen laptop"}, headers=hdr
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["revoked_user"] == "alice"
    assert body["binding"] == "device:alice"

    assert rdb.get("route:device:alice") is None
    assert client.get("/auth/verify", headers=bearer(victim)).status_code == 401


def test_admin_revoke_needs_an_identifier(client):
    hdr = bearer(admin_token(client))
    assert client.post("/admin/revoke", json={}, headers=hdr).status_code == 400
    assert client.post(
        "/admin/revoke", json={"device": "ghost"}, headers=hdr
    ).status_code == 404


# ---------------------------------------------------------------------------
# The probe can present a certificate
# ---------------------------------------------------------------------------
CERTS = Path(os.environ.get("AEGISX_CERTS_DIR", Path(__file__).resolve().parents[2] / "certs"))
needs_certs = pytest.mark.skipif(
    not (CERTS / "alice.crt").is_file(), reason="run scripts/gen_certs.sh first"
)


class _PlainListener:
    """A listener that speaks no TLS, so a TLS client fails the handshake."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            conn.close()

    def close(self):
        self._stop.set()
        self.sock.close()


@needs_certs
def test_probe_presenting_a_certificate_fails_closed_against_a_non_tls_peer(client):
    """The certificate is loaded and presented; a peer that cannot complete a
    TLS handshake must produce a specific negative verdict, never a hang or a
    false ALLOW. Depending on how the peer drops the connection the failure
    surfaces as a TLS error or a transport error -- both are reported."""
    listener = _PlainListener()
    try:
        body = client.post(
            "/demo/probe", json={"addr": "127.0.0.1:{}".format(listener.port), "cert": "alice"}
        ).json()
    finally:
        listener.close()

    assert body["tls"] is True, body
    assert body["allowed"] is False, body
    assert body["cert"] == "alice"
    assert body["device"] == "alice"
    assert body["reachable"] is False or body["tls_error"] is True, body
    assert body["detail"], body
    assert ("handshake" in body["detail"]) or ("not reachable" in body["detail"]), body


@needs_certs
def test_probe_rejects_certificate_names_outside_the_certs_directory(client):
    for bad in ("../ca", "..%2Fca", "foo/bar", "alice.crt"):
        resp = client.post("/demo/probe", json={"cert": bad})
        assert resp.status_code in (400, 404), bad


@needs_certs
def test_probe_reports_a_missing_certificate(client):
    resp = client.post("/demo/probe", json={"cert": "nobody"})
    assert resp.status_code == 404
