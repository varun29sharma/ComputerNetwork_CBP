"""Policy-as-data tests: seed, hot reload, CRUD, validation, admin-only access.

The policy cache is module-level, so every test invalidates it before and
after itself: conftest clears the Redis keys between tests, but the in-process
cache would otherwise serve the previous test's policy for up to 5 seconds.
"""
import pytest
from fastapi.testclient import TestClient

from app import identity
from app.main import app

CLIENT_IP = "203.0.113.40"


@pytest.fixture(autouse=True)
def _fresh_policy_cache():
    identity.invalidate_policy_cache()
    yield
    identity.invalidate_policy_cache()


def login(client, username, password, client_ip=CLIENT_IP, **extra):
    payload = {"username": username, "password": password, "client_ip": client_ip}
    payload.update(extra)
    return client.post("/auth/login", json=payload)


def bearer(token):
    return {"Authorization": "Bearer {}".format(token)}


def admin_headers(client):
    resp = login(client, "admin", "admin-console-pw")
    assert resp.status_code == 200, resp.text
    return bearer(resp.json()["access_token"])


def test_seed_loads_current_apps(client, rdb):
    resp = client.get("/admin/policy", headers=admin_headers(client))
    assert resp.status_code == 200, resp.text
    apps = resp.json()["apps"]
    assert apps["internal-api"]["target"] == "127.0.0.1:8080"
    assert apps["internal-api"]["posture"] == {"disk_encrypted": True}
    assert apps["internal-api"]["allowed_hours"] == ""
    assert apps["internal-api"]["session_ttl_seconds"] == 3600
    assert apps["internal-api"]["enabled"] is True
    assert apps["metrics-dashboard"]["target"] == "127.0.0.1:9090"
    assert apps["metrics-dashboard"]["posture"] == {}
    # Seeded in Redis, with the marker that stops a later re-seed.
    assert rdb.exists("policy:apps") == 1
    assert rdb.exists("policy:seeded") == 1


def test_hot_reload_posture_rule_flips_login_without_restart(client, rdb):
    # metrics-dashboard has no posture rules in the seed, so a failing claim
    # is allowed at first.
    assert login(client, "bob", "bob-analyst-pw",
                 posture={"disk_encrypted": False}).status_code == 200

    # Add the rule through the API -- same process, no restart.
    put = client.put(
        "/admin/policy/metrics-dashboard",
        json={"posture": {"disk_encrypted": True}},
        headers=admin_headers(client),
    )
    assert put.status_code == 200, put.text
    assert put.json()["posture"] == {"disk_encrypted": True}

    # The very next login is judged by the new rule.
    resp = login(client, "bob", "bob-analyst-pw", posture={"disk_encrypted": False})
    assert resp.status_code == 403
    assert "posture" in resp.json()["detail"]
    # ... and a passing claim still gets through.
    assert login(client, "bob", "bob-analyst-pw",
                 posture={"disk_encrypted": True}).status_code == 200


def test_put_target_change_takes_effect(client, rdb):
    put = client.put(
        "/admin/policy/internal-api", json={"target": "127.0.0.1:8081"},
        headers=admin_headers(client),
    )
    assert put.status_code == 200, put.text
    # A partial update keeps the fields it was not given.
    assert put.json()["posture"] == {"disk_encrypted": True}

    resp = login(client, "alice", "alice-dev-pw")
    assert resp.status_code == 200, resp.text
    assert resp.json()["target"] == "127.0.0.1:8081"
    assert rdb.get("route:{}".format(CLIENT_IP)) == "127.0.0.1:8081"


def test_delete_app_then_login_404s(client, rdb):
    resp = client.delete("/admin/policy/internal-api", headers=admin_headers(client))
    assert resp.status_code == 200, resp.text
    assert resp.json()["app"] == "internal-api"

    apps = client.get("/admin/policy", headers=admin_headers(client)).json()["apps"]
    assert "internal-api" not in apps

    resp = login(client, "alice", "alice-dev-pw", app="internal-api")
    assert resp.status_code == 404
    assert "unknown application" in resp.json()["detail"]
    assert rdb.get("route:{}".format(CLIENT_IP)) is None

    # Deleting an app that is already gone is a 404, not a silent success.
    resp = client.delete("/admin/policy/internal-api", headers=admin_headers(client))
    assert resp.status_code == 404


def test_create_app_requires_target_then_upsert_works(client):
    hdr = admin_headers(client)
    resp = client.put("/admin/policy/new-app", json={}, headers=hdr)
    assert resp.status_code == 422
    assert "target" in resp.json()["detail"]

    resp = client.put(
        "/admin/policy/new-app", json={"target": "127.0.0.1:7070"}, headers=hdr
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target"] == "127.0.0.1:7070"
    assert body["posture"] == {}
    assert body["allowed_hours"] == ""
    assert body["enabled"] is True

    apps = client.get("/admin/policy", headers=hdr).json()["apps"]
    assert "new-app" in apps


def test_invalid_target_422(client):
    hdr = admin_headers(client)
    for bad in ("not-a-target", "host:notaport", "host:0", "host:99999", ":8080", ""):
        resp = client.put(
            "/admin/policy/internal-api", json={"target": bad}, headers=hdr
        )
        assert resp.status_code == 422, bad
    # The bad writes changed nothing: the seed target is still in force.
    apps = client.get("/admin/policy", headers=hdr).json()["apps"]
    assert apps["internal-api"]["target"] == "127.0.0.1:8080"


def test_invalid_allowed_hours_422(client):
    hdr = admin_headers(client)
    for bad in ("25:00-26:00", "17:00-09:00", "09:00-09:00", "garbage", "9-17",
                "22:00-06:00"):
        resp = client.put(
            "/admin/policy/internal-api", json={"allowed_hours": bad}, headers=hdr
        )
        assert resp.status_code == 422, bad


def test_invalid_session_ttl_422(client):
    hdr = admin_headers(client)
    for bad in (0, 30, -1, 86401, 999999):
        resp = client.put(
            "/admin/policy/internal-api", json={"session_ttl_seconds": bad},
            headers=hdr,
        )
        assert resp.status_code == 422, bad
    # The bounds themselves are fine.
    for ok in (60, 86400):
        resp = client.put(
            "/admin/policy/internal-api", json={"session_ttl_seconds": ok},
            headers=hdr,
        )
        assert resp.status_code == 200, ok


def test_disabled_app_403_and_reenable_restores_login(client, rdb):
    hdr = admin_headers(client)
    assert client.put(
        "/admin/policy/internal-api", json={"enabled": False}, headers=hdr
    ).status_code == 200

    resp = login(client, "alice", "alice-dev-pw", app="internal-api")
    assert resp.status_code == 403
    assert "disabled" in resp.json()["detail"]
    assert rdb.get("route:{}".format(CLIENT_IP)) is None

    # Re-enabling is also a hot reload: no restart needed to restore access.
    assert client.put(
        "/admin/policy/internal-api", json={"enabled": True}, headers=hdr
    ).status_code == 200
    assert login(client, "alice", "alice-dev-pw").status_code == 200


def test_policy_endpoints_require_admin(client):
    assert client.get("/admin/policy").status_code == 401
    assert client.put("/admin/policy/internal-api", json={}).status_code == 401
    assert client.delete("/admin/policy/internal-api").status_code == 401

    alice = login(client, "alice", "alice-dev-pw").json()["access_token"]
    hdr = bearer(alice)
    assert client.get("/admin/policy", headers=hdr).status_code == 403
    assert client.put(
        "/admin/policy/internal-api", json={"enabled": False}, headers=hdr
    ).status_code == 403
    assert client.delete("/admin/policy/internal-api", headers=hdr).status_code == 403


def test_seed_never_overwrites_admin_edits_on_restart(client):
    hdr = admin_headers(client)
    assert client.put(
        "/admin/policy/internal-api", json={"target": "127.0.0.1:8081"},
        headers=hdr,
    ).status_code == 200

    # A fresh app instance (lifespan runs again) must see the admin edit,
    # not the seed defaults.
    identity.invalidate_policy_cache()
    with TestClient(app) as fresh:
        token = fresh.post(
            "/auth/login",
            json={"username": "admin", "password": "admin-console-pw",
                  "client_ip": CLIENT_IP},
        ).json()["access_token"]
        apps = fresh.get(
            "/admin/policy", headers=bearer(token)
        ).json()["apps"]
    assert apps["internal-api"]["target"] == "127.0.0.1:8081"
