"""Policy-engine tests: entitlements, device posture, admin identity rules."""
CLIENT_IP = "203.0.113.20"


def login(client, username, password, client_ip=CLIENT_IP, **extra):
    payload = {"username": username, "password": password, "client_ip": client_ip}
    payload.update(extra)
    return client.post("/auth/login", json=payload)


def test_entitlement_routes_identity_to_its_own_app(client):
    resp = login(client, "bob", "bob-analyst-pw")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["app"] == "metrics-dashboard"
    assert body["target"] == "127.0.0.1:9090"


def test_cross_app_request_is_denied_403(client, rdb):
    # alice is entitled to internal-api only: asking for bob's app must fail
    # before any route is written.
    resp = login(client, "alice", "alice-dev-pw", app="metrics-dashboard")
    assert resp.status_code == 403
    assert "not entitled" in resp.json()["detail"]
    assert rdb.get("route:{}".format(CLIENT_IP)) is None


def test_unknown_app_is_denied_404(client):
    resp = login(client, "alice", "alice-dev-pw", app="not-a-real-app")
    assert resp.status_code == 404


def test_failing_posture_claim_is_denied(client, rdb):
    resp = login(
        client, "alice", "alice-dev-pw", posture={"disk_encrypted": False}
    )
    assert resp.status_code == 403
    assert "posture" in resp.json()["detail"]
    assert rdb.get("route:{}".format(CLIENT_IP)) is None


def test_passing_posture_claim_is_allowed(client):
    resp = login(client, "alice", "alice-dev-pw", posture={"disk_encrypted": True})
    assert resp.status_code == 200
    assert resp.json()["posture"] == "pass"


def test_admin_identity_gets_no_data_plane_tunnel(client, rdb):
    resp = login(client, "admin", "admin-console-pw")
    assert resp.status_code == 200, resp.text
    assert resp.json()["target"] == ""
    assert resp.json()["route_key"] == ""
    assert rdb.get("route:{}".format(CLIENT_IP)) is None


def test_admin_endpoints_require_admin_role(client):
    assert client.get("/admin/sessions").status_code == 401

    alice = login(client, "alice", "alice-dev-pw").json()["access_token"]
    hdr = {"Authorization": "Bearer {}".format(alice)}
    # A valid non-admin token is authenticated but not authorized.
    assert client.get("/admin/sessions", headers=hdr).status_code == 403
    assert client.post(
        "/admin/revoke", json={"client_ip": CLIENT_IP}, headers=hdr
    ).status_code == 403


def test_apps_endpoint_describes_policy(client):
    apps = {a["name"]: a for a in client.get("/apps").json()}
    assert apps["internal-api"]["target"] == "127.0.0.1:8080"
    assert apps["internal-api"]["posture_rules"] == {"disk_encrypted": True}
