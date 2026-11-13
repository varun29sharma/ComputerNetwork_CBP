"""PEP reachability fields on /dashboard/state, against a stub listener.

The real Java PEP cannot run in this VM, so the tests point the app at a
plain listening socket (reachable) and at a closed port (unreachable) via
config.PEP_PROBE_ADDR -- a TCP connect is all the probe does.
"""
import socket

from app import config


def _free_port():
    """A port nothing is listening on: bind, read the number, close."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_pep_reachable_true_with_stub_listener(client, monkeypatch):
    # A listening socket answers the connect, so the PEP looks reachable
    # with a small local latency.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    monkeypatch.setattr(
        config, "PEP_PROBE_ADDR", "127.0.0.1:{}".format(server.getsockname()[1])
    )
    try:
        body = client.get("/dashboard/state").json()
    finally:
        server.close()
    assert body["pep_reachable"] is True
    assert isinstance(body["pep_latency_ms"], (int, float))
    assert 0 <= body["pep_latency_ms"] < 300


def test_pep_reachable_false_with_closed_port(client, monkeypatch):
    monkeypatch.setattr(
        config, "PEP_PROBE_ADDR", "127.0.0.1:{}".format(_free_port())
    )
    body = client.get("/dashboard/state").json()
    assert body["pep_reachable"] is False
    assert body["pep_latency_ms"] is None


def test_pep_reachable_false_with_bad_address(client, monkeypatch):
    # A malformed probe address is "unreachable", never a 500: the dashboard
    # feed must stay up even when the PEP config is wrong.
    monkeypatch.setattr(config, "PEP_PROBE_ADDR", "not-an-address")
    resp = client.get("/dashboard/state")
    assert resp.status_code == 200
    assert resp.json()["pep_reachable"] is False
