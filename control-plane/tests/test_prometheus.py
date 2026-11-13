"""Prometheus text-format metrics: /metrics/prometheus must render the same
counters the JSON /metrics endpoint exposes, plus an uptime gauge."""
import re

ALICE_PW = "alice-dev-pw"
CLIENT_IP = "198.51.100.7"

# Every counter state.metrics() exposes -- the Prometheus output must carry
# all of them, with the same values as the JSON endpoint.
COUNTERS = (
    "pep_allow_total",
    "pep_deny_total",
    "pep_closed_total",
    "pep_revoked_total",
    "logins_ok_total",
    "logins_denied_total",
    "admin_revocations_total",
    "pep_active_tunnels",
    "active_sessions",
)


def _metric_value(text, name):
    match = re.search(r"(?m)^{} (\d+(?:\.\d+)?)$".format(name), text)
    assert match, "{} missing from Prometheus output".format(name)
    return float(match.group(1))


def test_prometheus_is_plain_text_with_all_counters(client):
    resp = client.get("/metrics/prometheus")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    # Each metric gets a HELP + TYPE pair (the format Prometheus expects).
    assert "# HELP pep_allow_total" in resp.text
    assert "# TYPE pep_allow_total counter" in resp.text
    assert "# TYPE pep_active_tunnels gauge" in resp.text
    for name in COUNTERS:
        _metric_value(resp.text, name)


def test_prometheus_values_match_json_metrics_after_login(client):
    # A real login moves logins_ok_total and active_sessions, so the two
    # endpoints have something non-zero to agree on.
    login = client.post(
        "/auth/login",
        json={"username": "alice", "password": ALICE_PW, "client_ip": CLIENT_IP},
    )
    assert login.status_code == 200

    prometheus = client.get("/metrics/prometheus").text
    json_metrics = client.get("/metrics").json()
    assert json_metrics["logins_ok_total"] >= 1
    assert json_metrics["active_sessions"] >= 1
    for name in COUNTERS:
        assert _metric_value(prometheus, name) == json_metrics[name], name


def test_prometheus_uptime_present_and_non_negative(client):
    uptime = _metric_value(
        client.get("/metrics/prometheus").text, "aegisx_uptime_seconds"
    )
    assert uptime >= 0
