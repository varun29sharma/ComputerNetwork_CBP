"""Admin plane tests: session visibility, force-revocation, audit trail, metrics."""
ADMIN_IP = "203.0.113.30"
VICTIM_IP = "203.0.113.31"


def login(client, username, password, client_ip):
    return client.post(
        "/auth/login",
        json={"username": username, "password": password, "client_ip": client_ip},
    )


def bearer(token):
    return {"Authorization": "Bearer {}".format(token)}


def admin_token(client):
    resp = login(client, "admin", "admin-console-pw", ADMIN_IP)
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_sessions_list_shows_live_tunnel_with_identity(client):
    login(client, "alice", "alice-dev-pw", VICTIM_IP)
    sessions = client.get("/admin/sessions", headers=bearer(admin_token(client))).json()
    entry = next(s for s in sessions if s["client_ip"] == VICTIM_IP)
    assert entry["user"] == "alice"
    assert entry["app"] == "internal-api"
    assert entry["target"] == "127.0.0.1:8080"
    assert 0 < entry["ttl"] <= 3600


def test_force_revoke_kills_the_live_session(client, rdb):
    victim = login(client, "alice", "alice-dev-pw", VICTIM_IP).json()["access_token"]
    hdr = bearer(admin_token(client))
    assert rdb.get("route:{}".format(VICTIM_IP)) == "127.0.0.1:8080"

    resp = client.post(
        "/admin/revoke", json={"client_ip": VICTIM_IP, "reason": "lost laptop"}, headers=hdr
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["revoked_user"] == "alice"

    # Data plane: route gone. Control plane: token denylisted before its exp.
    assert rdb.get("route:{}".format(VICTIM_IP)) is None
    assert rdb.exists("jwt:deny:{}".format(body["jti"])) == 1
    assert client.get("/auth/verify", headers=bearer(victim)).status_code == 401
    assert all(
        s["client_ip"] != VICTIM_IP
        for s in client.get("/admin/sessions", headers=hdr).json()
    )


def test_force_revoke_unknown_session_404(client):
    resp = client.post(
        "/admin/revoke", json={"client_ip": "198.51.100.99"}, headers=bearer(admin_token(client))
    )
    assert resp.status_code == 404


def test_audit_stream_records_decisions(client):
    login(client, "alice", "alice-dev-pw", VICTIM_IP)
    login(client, "alice", "wrong-password", VICTIM_IP)
    events = client.get("/admin/audit", headers=bearer(admin_token(client))).json()
    names = {e["event"] for e in events}
    assert "login.success" in names
    assert "tunnel.provisioned" in names
    assert "login.fail" in names or "login.invalid_credentials" in names or "login.ratelimit" in names
    # Newest first, and every entry carries a stream id + timestamp.
    assert events[0]["id"] > events[-1]["id"]
    assert all("ts" in e for e in events)


def test_metrics_counters_move(client):
    before = client.get("/metrics").json()
    login(client, "alice", "alice-dev-pw", VICTIM_IP)
    after = client.get("/metrics").json()
    assert after["logins_ok_total"] == before["logins_ok_total"] + 1
    assert after["active_sessions"] >= 1
