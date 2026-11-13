"""Real-TCP probe tests: /demo/probe must speak actual TCP, not read Redis.

Two local listeners stand in for the gateway: one that answers with an HTTP
response (the "authorized tunnel" case) and one that accepts and immediately
closes without a payload (exactly how the cloaked PEP behaves).
"""
import socket
import threading

import pytest


class _Listener:
    def __init__(self, reply: bytes):
        self.reply = reply
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                if self.reply:
                    try:
                        conn.recv(1024)
                        conn.sendall(self.reply)
                    except OSError:
                        pass
                # reply == b"" -> accept and close with no payload (cloaked)

    def close(self):
        self._stop.set()
        self.sock.close()


@pytest.fixture()
def open_tunnel():
    listener = _Listener(b"HTTP/1.0 200 OK\r\n\r\nhello from aegisx-demo-target")
    yield "127.0.0.1:{}".format(listener.port)
    listener.close()


@pytest.fixture()
def cloaked_gateway():
    listener = _Listener(b"")
    yield "127.0.0.1:{}".format(listener.port)
    listener.close()


def probe(client, addr):
    return client.post("/demo/probe", json={"addr": addr})


def test_probe_reports_allow_when_target_answers(client, open_tunnel):
    resp = probe(client, open_tunnel)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["reachable"] is True
    assert body["allowed"] is True
    assert "aegisx-demo-target" not in body["detail"] or "200" in body["detail"]
    assert "proxied" in body["detail"]


def test_probe_reports_cloak_when_connection_is_dropped(client, cloaked_gateway):
    body = probe(client, cloaked_gateway).json()
    assert body["reachable"] is True
    assert body["allowed"] is False
    assert "cloaked" in body["detail"]


def test_probe_reports_unreachable_gateway(client):
    body = probe(client, "127.0.0.1:9").json()
    assert body["reachable"] is False
    assert body["allowed"] is False
    assert "not reachable" in body["detail"]


def test_probe_rejects_malformed_address(client):
    assert probe(client, "not-an-address").status_code == 400


def test_probe_defaults_to_the_configured_pep(client):
    # With no body the probe uses AEGISX_PEP_PROBE_ADDR; the response always
    # echoes which address it actually dialled.
    body = client.post("/demo/probe").json()
    assert body["addr"] == "127.0.0.1:9000"
