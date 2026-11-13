"""Dashboard endpoint tests: the UI page and its live state feed."""
import shutil
import subprocess
from pathlib import Path

import pytest

ALICE_PW = "alice-dev-pw"
CLIENT_IP = "198.51.100.7"
APP_JS = Path(__file__).resolve().parents[1] / "app" / "static" / "app.js"


def login(client, username="alice", password=ALICE_PW, client_ip=CLIENT_IP):
    return client.post(
        "/auth/login", json={"username": username, "password": password, "client_ip": client_ip}
    )


def test_dashboard_page_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    # The page must carry the explainer + the live-demo hooks.
    for marker in ("AegisX", "Zero Trust", "/auth/login", "/dashboard/state", "CLOAKED"):
        assert marker in resp.text
    # ...and the newer capabilities the demo now exercises.
    for marker in ("/demo/probe", "/admin/sessions", "posture", "audit"):
        assert marker in resp.text


def test_dashboard_alias_serves_the_same_page(client):
    assert client.get("/dashboard").status_code == 200


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_dashboard_javascript_parses():
    """The dashboard JS lives in app.js (split out of index.html in the UI
    rebuild), so a JavaScript syntax error breaks every interaction while the
    HTML still serves fine -- markers alone would not notice. Parse it for real."""
    assert APP_JS.exists(), "app.js missing -- the dashboard split is incomplete"
    result = subprocess.run(
        [shutil.which("node"), "--check", str(APP_JS)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_dashboard_exposes_the_device_binding_controls(client):
    """The certificate identity has to be reachable from the UI, not only the API."""
    resp = client.get("/")
    for marker in ('id="device"', 'id="probe-cert"', "/admin/revoke"):
        assert marker in resp.text


def test_dashboard_has_the_attempt_visualization(client):
    """The cross-application attempt panel and its animated flow diagram."""
    resp = client.get("/")
    for marker in (
        'id="flowviz"',            # the SVG diagram
        'id="btn-attempt"',        # the real attempt button
        "/demo/attempt",            # the endpoint it calls
        'id="attempt-trace"',       # the gate-by-gate trace
        'id="btn-story"',           # the open-then-revoke narrative
        "Watch a decision happen",
    ):
        assert marker in resp.text, marker


def test_dashboard_state_empty(client):
    body = client.get("/dashboard/state").json()
    assert body["routes"] == []
    assert body["denylisted"] == []
    assert body["rate_limits"] == []
    assert body["sessions"] == []
    assert body["lockouts"] == []
    # The extended feed always carries these, even when nothing happened yet.
    for key in ("audit", "metrics", "apps", "pep_addr", "route_ttl"):
        assert key in body
    assert body["metrics"]["pep_allow_total"] == 0


def test_dashboard_state_tracks_login_and_revocation(client):
    login(client)
    body = client.get("/dashboard/state").json()
    route = next(r for r in body["routes"] if r["client_ip"] == CLIENT_IP)
    assert route["target"] == "127.0.0.1:8080"
    assert 0 < route["ttl"] <= 3600
    assert any(rl["username"] == "alice" for rl in body["rate_limits"])

    # The session record joins the PEP's route key with the PDP's identity view.
    session = next(s for s in body["sessions"] if s["client_ip"] == CLIENT_IP)
    assert session["user"] == "alice"
    assert session["app"] == "internal-api"
    assert any(e["event"] == "tunnel.provisioned" for e in body["audit"])

    token = login(client).json()["access_token"]
    client.post("/auth/logout", headers={"Authorization": "Bearer {}".format(token)})

    body = client.get("/dashboard/state").json()
    assert all(r["client_ip"] != CLIENT_IP for r in body["routes"])
    assert len(body["denylisted"]) == 1
    assert 0 < body["denylisted"][0]["ttl"] <= 3600
    assert body["sessions"] == []
    assert any(e["event"] == "logout" for e in body["audit"])
