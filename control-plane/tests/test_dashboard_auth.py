"""Dashboard auth flag (backend half): with AEGISX_DASHBOARD_AUTH=1,
/dashboard/state shows sensitive fields only to a valid admin token; without
a token (or with a non-admin token) it returns a 200 redacted view. With the
flag off (default) the feed is exactly as before -- full state, no auth.

The dashboard JS half (sending the admin token) is separate work; these
tests cover the backend gate only.
"""
from app import config

ALICE_PW = "alice-dev-pw"
ADMIN_PW = "admin-console-pw"
CLIENT_IP = "198.51.100.7"

# Aggregate counters + static config: safe to show anyone.
PUBLIC_KEYS = {
    "metrics", "apps", "pep_reachable", "pep_latency_ms",
    "posture_strict", "route_ttl", "certs", "pep_addr",
}
# Anything that identifies a live session or user.
SENSITIVE_KEYS = {
    "sessions", "audit", "routes", "denylisted",
    "rate_limits", "lockouts", "users",
}


def _login(client, username, password):
    resp = client.post(
        "/auth/login",
        json={"username": username, "password": password, "client_ip": CLIENT_IP},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_flag_off_full_state_with_no_token(client):
    # Default behaviour: no flag, no token, everything visible.
    _login(client, "alice", ALICE_PW)
    body = client.get("/dashboard/state").json()
    assert SENSITIVE_KEYS <= set(body)
    assert PUBLIC_KEYS <= set(body)
    assert body["sessions"], "a login must show up in the full feed"


def test_flag_on_no_token_redacted(client, monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_AUTH", True)
    _login(client, "alice", ALICE_PW)  # prove there IS sensitive data to hide
    resp = client.get("/dashboard/state")
    assert resp.status_code == 200  # redacted view, not an error
    body = resp.json()
    assert set(body) == PUBLIC_KEYS
    assert "sessions" not in body
    assert "audit" not in body


def test_flag_on_admin_token_full_state(client, monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_AUTH", True)
    _login(client, "alice", ALICE_PW)
    admin_token = _login(client, "admin", ADMIN_PW)
    body = client.get(
        "/dashboard/state", headers={"Authorization": "Bearer " + admin_token}
    ).json()
    assert SENSITIVE_KEYS <= set(body)
    assert PUBLIC_KEYS <= set(body)
    assert body["sessions"], "admin must see the live sessions"


def test_flag_on_non_admin_token_redacted(client, monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_AUTH", True)
    alice_token = _login(client, "alice", ALICE_PW)
    body = client.get(
        "/dashboard/state", headers={"Authorization": "Bearer " + alice_token}
    ).json()
    assert set(body) == PUBLIC_KEYS


def test_flag_on_bogus_token_redacted(client, monkeypatch):
    monkeypatch.setattr(config, "DASHBOARD_AUTH", True)
    body = client.get(
        "/dashboard/state", headers={"Authorization": "Bearer not-a-real-token"}
    ).json()
    assert set(body) == PUBLIC_KEYS
