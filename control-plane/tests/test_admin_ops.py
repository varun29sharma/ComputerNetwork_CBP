"""Admin operations: device enrollment + revocation, user management,
lockout management, emergency lockdown, audit export, live-policy /apps.

One admin login per test: an admin login carries no app, so the login gate
counts it as a failed attempt -- five of them in one test would lock the
admin account (see the lockout test for why that is by design).
"""
import json

ADMIN_IP = "203.0.113.50"


def login(client, username, password, client_ip, **extra):
    payload = {"username": username, "password": password, "client_ip": client_ip}
    payload.update(extra)
    return client.post("/auth/login", json=payload)


def bearer(token):
    return {"Authorization": "Bearer {}".format(token)}


def admin_token(client):
    resp = login(client, "admin", "admin-console-pw", ADMIN_IP)
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def create_user(client, hdr, username, password="some-password-1", **extra):
    body = {"username": username, "password": password, "role": "developer",
            "apps": ["internal-api"]}
    body.update(extra)
    return client.post("/admin/users", json=body, headers=hdr)


# ---------------------------------------------------------------------------
# Device enrollment + revocation
# ---------------------------------------------------------------------------
def test_device_register_then_login_asserts_it(client, rdb):
    rdb.delete("users:carol")
    hdr = bearer(admin_token(client))
    assert create_user(client, hdr, "carol").status_code == 201

    resp = client.post(
        "/admin/devices", json={"username": "carol", "device": "carol-laptop"}, headers=hdr
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["device"] == "carol-laptop"

    resp = login(client, "carol", "some-password-1", "203.0.113.51", device="carol-laptop")
    assert resp.status_code == 200, resp.text
    assert resp.json()["binding"] == "device:carol-laptop"
    assert rdb.get("route:device:carol-laptop") == "127.0.0.1:8080"


def test_device_register_unknown_user_404(client):
    hdr = bearer(admin_token(client))
    resp = client.post(
        "/admin/devices", json={"username": "ghost", "device": "ghost-laptop"}, headers=hdr
    )
    assert resp.status_code == 404


def test_device_revoke_blocks_login_and_kills_live_session(client, rdb):
    rdb.delete("users:carol")
    hdr = bearer(admin_token(client))
    assert create_user(client, hdr, "carol").status_code == 201
    client.post(
        "/admin/devices", json={"username": "carol", "device": "carol-laptop"}, headers=hdr
    )
    token = login(
        client, "carol", "some-password-1", "203.0.113.51", device="carol-laptop"
    ).json()["access_token"]
    assert rdb.get("route:device:carol-laptop") == "127.0.0.1:8080"

    resp = client.post(
        "/admin/devices/revoke", json={"device": "carol-laptop"}, headers=hdr
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["sessions_revoked"] == 1

    # The deny key blocks new logins; the revoked route kills the open tunnel.
    assert rdb.exists("cert:deny:carol-laptop") == 1
    assert 0 < rdb.ttl("cert:deny:carol-laptop") <= 86400
    assert rdb.get("route:device:carol-laptop") is None
    assert rdb.exists("sess:device:carol-laptop") == 0
    assert client.get("/auth/verify", headers=bearer(token)).status_code == 401

    resp = login(client, "carol", "some-password-1", "203.0.113.51", device="carol-laptop")
    assert resp.status_code == 403
    assert "revoked" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------
def test_user_create_disable_enable_lifecycle(client, rdb):
    rdb.delete("users:dave")
    hdr = bearer(admin_token(client))
    resp = create_user(client, hdr, "dave")
    assert resp.status_code == 201, resp.text
    assert resp.json() == {
        "username": "dave", "role": "developer",
        "apps": ["internal-api"], "device": "",
    }

    ip = "203.0.113.52"
    assert login(client, "dave", "some-password-1", ip).status_code == 200
    assert rdb.get("route:{}".format(ip)) == "127.0.0.1:8080"

    resp = client.post("/admin/users/dave/disable", headers=hdr)
    assert resp.status_code == 200, resp.text
    assert resp.json()["sessions_revoked"] == 1
    # Disabled looks exactly like a bad password: 401, and no route is left.
    assert login(client, "dave", "some-password-1", ip).status_code == 401
    assert rdb.get("route:{}".format(ip)) is None

    resp = client.post("/admin/users/dave/enable", headers=hdr)
    assert resp.status_code == 200
    assert login(client, "dave", "some-password-1", ip).status_code == 200


def test_user_create_duplicate_409(client, rdb):
    rdb.delete("users:erin")
    hdr = bearer(admin_token(client))
    assert create_user(client, hdr, "erin").status_code == 201
    assert create_user(client, hdr, "erin").status_code == 409


def test_user_create_validation_422(client, rdb):
    rdb.delete("users:mallory", "users:trent", "users:oscar")
    hdr = bearer(admin_token(client))
    assert create_user(client, hdr, "mallory", role="superuser").status_code == 422
    assert create_user(client, hdr, "trent", apps=["not-a-real-app"]).status_code == 422
    assert create_user(client, hdr, "oscar", password="short").status_code == 422


def test_user_disable_unknown_404(client):
    hdr = bearer(admin_token(client))
    assert client.post("/admin/users/ghost/disable", headers=hdr).status_code == 404
    assert client.post("/admin/users/ghost/enable", headers=hdr).status_code == 404


# ---------------------------------------------------------------------------
# Lockout management
# ---------------------------------------------------------------------------
def test_lockout_list_and_unlock(client, rdb):
    hdr = bearer(admin_token(client))
    ip = "203.0.113.53"
    for _ in range(4):
        assert login(client, "alice", "wrong-password", ip).status_code == 401
    # Fifth consecutive failure locks the account (LOGIN_FAIL_MAX=5).
    assert login(client, "alice", "wrong-password", ip).status_code == 423

    lockouts = client.get("/admin/lockouts", headers=hdr).json()
    assert any(u["username"] == "alice" and 0 < u["remaining_seconds"] <= 300
               for u in lockouts["users"])
    # The attack IP opened a rate window (ipl:*), but it is not locked out:
    # it is listed under rate_limited_ips, and the old "ips" key is gone.
    assert "ips" not in lockouts
    assert any(e["ip"] == ip and 0 < e["remaining_seconds"]
               for e in lockouts["rate_limited_ips"])

    resp = client.post("/admin/unlock", json={"username": "alice"}, headers=hdr)
    assert resp.status_code == 200, resp.text
    lockouts = client.get("/admin/lockouts", headers=hdr).json()
    assert all(u["username"] != "alice" for u in lockouts["users"])

    # Unlock clears the lock, not the per-user rate window: the next login is
    # rate-limited (429), which itself proves the account is no longer locked.
    assert login(client, "alice", "alice-dev-pw", ip).status_code == 429
    rdb.delete("login:rl:alice")
    assert login(client, "alice", "alice-dev-pw", ip).status_code == 200


def test_unlock_needs_a_target_422(client):
    hdr = bearer(admin_token(client))
    assert client.post("/admin/unlock", json={}, headers=hdr).status_code == 422


def test_single_login_opens_rate_window_not_lockout(client):
    hdr = bearer(admin_token(client))
    ip = "203.0.113.57"
    # One ordinary login, nowhere near the per-IP limit: it opens a rate
    # window (ipl:*), but it is not a lockout -- so it must appear under
    # rate_limited_ips and the user must not appear under users.
    assert login(client, "alice", "alice-dev-pw", ip).status_code == 200
    lockouts = client.get("/admin/lockouts", headers=hdr).json()
    assert any(e["ip"] == ip and 0 < e["remaining_seconds"]
               for e in lockouts["rate_limited_ips"])
    assert all(u["username"] != "alice" for u in lockouts["users"])


# ---------------------------------------------------------------------------
# Emergency lockdown
# ---------------------------------------------------------------------------
def test_lockdown_blocks_login_and_revokes_sessions(client, rdb):
    hdr = bearer(admin_token(client))
    ip = "203.0.113.54"
    assert login(client, "alice", "alice-dev-pw", ip).status_code == 200
    assert rdb.get("route:{}".format(ip)) == "127.0.0.1:8080"

    resp = client.post("/admin/lockdown", json={"on": True}, headers=hdr)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"lockdown": True, "sessions_revoked": 1}
    assert rdb.get("route:{}".format(ip)) is None
    assert client.get("/admin/lockdown", headers=hdr).json() == {"lockdown": True}
    assert client.get("/dashboard/state").json()["lockdown"] is True

    resp = login(client, "alice", "alice-dev-pw", ip)
    assert resp.status_code == 403
    assert "lockdown" in resp.json()["detail"]

    resp = client.post("/admin/lockdown", json={"on": False}, headers=hdr)
    assert resp.json() == {"lockdown": False, "sessions_revoked": 0}
    assert client.get("/dashboard/state").json()["lockdown"] is False
    assert login(client, "alice", "alice-dev-pw", ip).status_code == 200


# ---------------------------------------------------------------------------
# Audit export + live-policy /apps + admin-only enforcement
# ---------------------------------------------------------------------------
def test_audit_export_json_and_csv(client):
    hdr = bearer(admin_token(client))
    assert login(client, "alice", "alice-dev-pw", "203.0.113.55").status_code == 200

    resp = client.get("/admin/audit/export", headers=hdr)
    assert resp.status_code == 200, resp.text
    assert "attachment" in resp.headers["content-disposition"]
    events = json.loads(resp.text)
    assert any(e["event"] == "login.success" for e in events)

    resp = client.get("/admin/audit/export?format=csv", headers=hdr)
    assert resp.status_code == 200, resp.text
    assert "attachment" in resp.headers["content-disposition"]
    lines = resp.text.strip().splitlines()
    assert lines[0] == "timestamp,event,subject,client_ip,app,detail"
    assert any("login.success" in line for line in lines[1:])

    assert client.get("/admin/audit/export?format=xml", headers=hdr).status_code == 422


def test_apps_reflects_policy_change(client):
    hdr = bearer(admin_token(client))
    before = {a["name"]: a for a in client.get("/apps").json()}
    assert before["internal-api"]["target"] == "127.0.0.1:8080"

    resp = client.put(
        "/admin/policy/internal-api",
        json={"target": "127.0.0.1:8081", "posture": {"disk_encrypted": False}},
        headers=hdr,
    )
    assert resp.status_code == 200, resp.text

    after = {a["name"]: a for a in client.get("/apps").json()}
    assert after["internal-api"]["target"] == "127.0.0.1:8081"
    assert after["internal-api"]["posture_rules"] == {"disk_encrypted": False}
    admin_after = {a["name"]: a for a in client.get("/admin/apps", headers=hdr).json()}
    assert admin_after["internal-api"]["target"] == "127.0.0.1:8081"


def test_non_admin_cannot_use_admin_operations(client):
    alice = login(client, "alice", "alice-dev-pw", "203.0.113.56").json()["access_token"]
    hdr = bearer(alice)
    assert client.post("/admin/devices", json={"username": "alice", "device": "x"}, headers=hdr).status_code == 403
    assert client.post("/admin/users", json={"username": "z", "password": "some-password-1", "role": "developer"}, headers=hdr).status_code == 403
    assert client.get("/admin/lockouts", headers=hdr).status_code == 403
    assert client.post("/admin/unlock", json={"username": "alice"}, headers=hdr).status_code == 403
    assert client.post("/admin/lockdown", json={"on": True}, headers=hdr).status_code == 403
    assert client.get("/admin/audit/export", headers=hdr).status_code == 403
