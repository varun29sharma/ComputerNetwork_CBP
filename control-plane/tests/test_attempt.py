"""The cross-application attempt trace: where an attempt to reach an application
you are not entitled to is stopped, and what the wire would deliver."""
CLIENT_IP = "203.0.113.60"


def login(client, username, password, client_ip=CLIENT_IP, **extra):
    payload = {"username": username, "password": password, "client_ip": client_ip}
    payload.update(extra)
    return client.post("/auth/login", json=payload)


def bearer(token):
    return {"Authorization": "Bearer {}".format(token)}


def attempt(client, token, app, cert=None):
    body = {"app": app}
    if cert:
        body["cert"] = cert
    return client.post("/demo/attempt", json=body, headers=bearer(token))


def test_attempt_requires_a_verified_token(client):
    assert client.post("/demo/attempt", json={"app": "internal-api"}).status_code == 401
    resp = client.post(
        "/demo/attempt", json={"app": "internal-api"}, headers=bearer("garbage")
    )
    assert resp.status_code == 401


def test_entitled_attempt_traces_every_gate(client, rdb):
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]
    resp = attempt(client, token, "internal-api")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["identity"] == "alice"
    assert body["requested_app"] == "internal-api"
    assert body["requested_target"] == "127.0.0.1:8080"
    # Gates are reported in enforcement order and the first three all pass:
    # identity -> entitlement -> authorization record.
    names = [s["stage"] for s in body["stages"]]
    assert names[:3] == ["identity", "entitlement", "route"]
    assert all(s["ok"] for s in body["stages"][:3])
    assert body["route_key"] == "route:{}".format(CLIENT_IP)
    assert body["route_target"] == "127.0.0.1:8080"
    assert body["decision"] == "ALLOW"


def test_cross_application_attempt_is_denied_by_the_policy_engine(client, rdb):
    """The headline case: a valid, logged-in session asking for an application
    it is not entitled to. It must stop at the policy engine, before any
    authorization record is written."""
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]

    resp = attempt(client, token, "metrics-dashboard")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["decision"] == "DENY"
    assert body["decided_by"] == "policy-engine"
    assert "not entitled" in body["reason"]
    assert body["requested_target"] == "127.0.0.1:9090"

    # The entitlement gate is the one that failed; identity passed.
    stages = {s["stage"]: s for s in body["stages"]}
    assert stages["identity"]["ok"] is True
    assert stages["entitlement"]["ok"] is False
    assert "metrics-dashboard" in stages["entitlement"]["detail"]
    # The data plane was never consulted for a denied request.
    assert body["gateway"] is None

    # A denied attempt leaves no route behind, and alice's existing route to
    # her designated app is untouched -- she still cannot reach :9090.
    assert rdb.get("route:{}".format(CLIENT_IP)) == "127.0.0.1:8080"
    assert rdb.get("route:device:alice") is None


def test_unknown_application_is_denied_not_crashed(client):
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]
    body = attempt(client, token, "not-a-real-app").json()
    assert body["decision"] == "DENY"
    assert body["decided_by"] == "policy-engine"
    assert "unknown application" in body["reason"]


def test_denied_attempt_explains_what_the_identity_can_reach(client):
    """The trace must contrast the app that was asked for with the one the
    session's authorization record actually delivers."""
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]
    body = attempt(client, token, "metrics-dashboard").json()
    assert body["requested_target"] == "127.0.0.1:9090"
    assert body["route_target"] == "127.0.0.1:8080"
    assert body["entitled_apps"] == ["internal-api"]


def test_entitled_attempt_without_a_route_is_denied_by_the_gateway(client, rdb):
    """Entitled identity, but no authorization record (TTL expired, or revoked
    elsewhere) -- the gateway gate must refuse it, and say why."""
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]
    rdb_key = "route:{}".format(CLIENT_IP)
    assert rdb.get(rdb_key) == "127.0.0.1:8080"

    # The route vanishes while the token is still perfectly valid: this is the
    # continuous-verification case the PEP enforces on every connection.
    rdb.delete(rdb_key)

    body = attempt(client, token, "internal-api").json()
    assert body["decision"] == "DENY"
    assert body["decided_by"] == "gateway"
    assert "not in Redis" in body["reason"]
    stages = {s["stage"]: s for s in body["stages"]}
    assert stages["identity"]["ok"] is True
    assert stages["entitlement"]["ok"] is True
    assert stages["route"]["ok"] is False
    assert body["gateway"] is None


def test_wire_result_is_reported_separately_from_the_policy_verdict(client):
    """A gateway that cannot be reached must not be reported as a policy
    denial -- the policy verdict stays ALLOW and the wire result says why."""
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]
    body = client.post(
        "/demo/attempt",
        json={"app": "internal-api", "addr": "127.0.0.1:9"},  # nothing listens
        headers=bearer(token),
    ).json()

    assert body["decision"] == "ALLOW", body
    assert body["decided_by"] == ""
    assert body["wire"] == "unavailable"
    assert "not reachable" in body["gateway"]["detail"]
    stages = {s["stage"]: s for s in body["stages"]}
    assert stages["route"]["ok"] is True
    assert stages["gateway"]["ok"] is False


def test_denied_attempt_performs_no_wire_check(client):
    token = login(client, "alice", "alice-dev-pw").json()["access_token"]
    body = attempt(client, token, "metrics-dashboard").json()
    assert body["decision"] == "DENY"
    assert body["wire"] == ""          # the data plane was never consulted
    assert body["gateway"] is None


def test_admin_identity_has_no_application_entitlement(client):
    token = login(client, "admin", "admin-console-pw").json()["access_token"]
    body = attempt(client, token, "internal-api").json()
    assert body["decision"] == "DENY"
    assert body["decided_by"] == "policy-engine"
    assert body["entitled_apps"] == []
