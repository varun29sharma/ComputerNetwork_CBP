"""Time rules + per-app TTL tests.

The clock is never trusted: every test monkeypatches identity.policy_now to a
fixed local time, so results are the same no matter when the suite runs.
"""
from datetime import datetime

import pytest

from app import identity

CLIENT_IP = "203.0.113.41"
WINDOW = "09:00-17:00"


@pytest.fixture(autouse=True)
def _fresh_policy_cache():
    identity.invalidate_policy_cache()
    yield
    identity.invalidate_policy_cache()


def login(client, username="alice", password="alice-dev-pw", client_ip=CLIENT_IP):
    return client.post(
        "/auth/login",
        json={"username": username, "password": password, "client_ip": client_ip},
    )


def bearer(token):
    return {"Authorization": "Bearer {}".format(token)}


def admin_headers(client):
    resp = login(client, "admin", "admin-console-pw")
    assert resp.status_code == 200, resp.text
    return bearer(resp.json()["access_token"])


def set_policy(client, app, **fields):
    resp = client.put(
        "/admin/policy/{}".format(app), json=fields, headers=admin_headers(client)
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def freeze_clock(monkeypatch, hour, minute=0):
    """Pin policy_now to a fixed local time (the date itself is irrelevant)."""
    frozen = datetime(2026, 11, 13, hour, minute)
    monkeypatch.setattr(identity, "policy_now", lambda: frozen)


def test_inside_window_login_allowed(client, monkeypatch):
    set_policy(client, "internal-api", allowed_hours=WINDOW)
    freeze_clock(monkeypatch, 12, 0)
    resp = login(client)
    assert resp.status_code == 200, resp.text
    assert resp.json()["app"] == "internal-api"


def test_window_edges_start_inclusive_end_exclusive(client, monkeypatch):
    set_policy(client, "internal-api", allowed_hours=WINDOW)
    # Exactly at the start of the window: allowed.
    freeze_clock(monkeypatch, 9, 0)
    assert login(client).status_code == 200
    # Exactly at the end of the window: the window has closed.
    freeze_clock(monkeypatch, 17, 0)
    resp = login(client)
    assert resp.status_code == 403
    assert WINDOW in resp.json()["detail"]


def test_outside_window_login_denied_with_window_in_message(client, monkeypatch, rdb):
    set_policy(client, "internal-api", allowed_hours=WINDOW)
    freeze_clock(monkeypatch, 20, 30)
    resp = login(client)
    assert resp.status_code == 403
    assert WINDOW in resp.json()["detail"]
    # A denied login leaves no tunnel behind.
    assert rdb.get("route:{}".format(CLIENT_IP)) is None

    # Before the window opens is denied the same way.
    freeze_clock(monkeypatch, 8, 59)
    resp = login(client)
    assert resp.status_code == 403
    assert WINDOW in resp.json()["detail"]


def test_empty_allowed_hours_always_allowed(client, monkeypatch):
    # The seed record has allowed_hours "" -- usable at 3 AM.
    freeze_clock(monkeypatch, 3, 0)
    assert login(client).status_code == 200

    # Clearing the window explicitly restores always-allowed too.
    set_policy(client, "internal-api", allowed_hours=WINDOW)
    freeze_clock(monkeypatch, 20, 0)
    assert login(client).status_code == 403
    set_policy(client, "internal-api", allowed_hours="")
    assert login(client).status_code == 200


def test_per_app_ttl_sets_route_and_session_ttl_not_jwt(client, rdb):
    set_policy(client, "internal-api", session_ttl_seconds=120)
    resp = login(client)
    assert resp.status_code == 200, resp.text

    # The route key lives as long as the app's policy says (a few seconds of
    # slack for the time between the login and these reads).
    route_ttl = rdb.ttl("route:{}".format(CLIENT_IP))
    assert 110 <= route_ttl <= 120, route_ttl
    sess_ttl = rdb.ttl("sess:{}".format(CLIENT_IP))
    assert 110 <= sess_ttl <= 120, sess_ttl

    # ... but the JWT lifetime is untouched: still the global default.
    assert resp.json()["expires_in"] == 3600
