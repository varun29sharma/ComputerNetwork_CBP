"""Service accounts: an API key (shown once) exchanges for a role=service
JWT good for exactly one app. Only the key's SHA-256 hash is ever stored."""
import hashlib

import jwt as pyjwt

TEST_SECRET = "test-secret-0123456789abcdef0123456789abcdef"
ADMIN_IP = "203.0.113.50"


def admin_token(client):
    resp = client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin-console-pw", "client_ip": ADMIN_IP},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_create_exchange_and_hash_storage(client, rdb):
    hdr = {"Authorization": "Bearer {}".format(admin_token(client))}
    resp = client.post(
        "/admin/service-accounts", json={"name": "reporter", "app": "internal-api"}, headers=hdr
    )
    assert resp.status_code == 201, resp.text
    key = resp.json()["api_key"]
    assert key

    # The stored value is the hash, never the key itself.
    stored = rdb.hgetall("svc:reporter")
    assert stored["app"] == "internal-api"
    assert stored["key_hash"] == hashlib.sha256(key.encode()).hexdigest()
    assert stored["key_hash"] != key

    resp = client.post("/auth/service", json={"name": "reporter", "api_key": key})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["app"] == "internal-api"
    assert body["target"] == "127.0.0.1:8080"
    claims = pyjwt.decode(body["access_token"], TEST_SECRET, algorithms=["HS256"])
    assert claims["sub"] == "reporter"
    assert claims["role"] == "service"
    assert rdb.get("route:testclient") == "127.0.0.1:8080"


def test_wrong_key_401_duplicate_409_unknown_app_422(client):
    hdr = {"Authorization": "Bearer {}".format(admin_token(client))}
    resp = client.post(
        "/admin/service-accounts", json={"name": "scraper", "app": "internal-api"}, headers=hdr
    )
    assert resp.status_code == 201, resp.text
    assert client.post(
        "/auth/service", json={"name": "scraper", "api_key": "not-the-key"}
    ).status_code == 401
    assert client.post(
        "/admin/service-accounts", json={"name": "scraper", "app": "internal-api"}, headers=hdr
    ).status_code == 409
    assert client.post(
        "/admin/service-accounts", json={"name": "other", "app": "not-a-real-app"}, headers=hdr
    ).status_code == 422
