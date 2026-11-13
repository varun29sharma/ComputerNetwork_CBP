# AegisX — Identity-Aware Zero Trust Network Access Gateway

A ZTNA gateway that replaces implicit-trust VPNs with **Authenticate-Before-Connect**:
nobody reaches a protected app until the control plane has authenticated them and
written a one-identity, one-app micro-tunnel into Redis. Python (FastAPI) control
plane, Java (Netty) data plane, Redis as the state broker between them.

## Architecture

```
Client ──1. POST /auth/login──▶ PDP (FastAPI :8000, Policy Decision Point)
                                    │ 2. SET route:<binding> = host:port
                                    ▼
                               Redis :6379 (state broker)
                                    ▲
Client ──3. TCP connect──────▶ PEP (Netty :9000, Policy Enforcement Point)
                                    │ 4. GET route:<binding> (re-read every 5 s)
                                    ▼
                               Protected app :8080 (only if a route exists)

No arrow runs PDP → PEP: the PDP never calls the PEP. Redis is the only
link between the planes.
```

Full version with the data flow, the Redis key schema and the two Lua scripts:
[docs/architecture.md](docs/architecture.md).

## What's new in batch 2 (Nov 2026)

- **Policy-as-data + hot reload**: app policy lives in Redis (`policy:apps`),
  edited via `GET/PUT/DELETE /admin/policy` or the dashboard policy editor —
  the next login is judged by the new rules, no restart.
- **Time rules + per-app TTL**: `allowed_hours` windows and
  `session_ttl_seconds` per app (JWT lifetime unchanged).
- **TLS on the control plane**: `./scripts/run_all.sh --tls`
  (dedicated PDP cert, `certs/pdp.crt`); plain HTTP stays the default.
- **Device enrollment + cert revocation**: `scripts/enroll_device.sh`,
  `POST /admin/devices[/revoke]`; the PEP checks `cert:deny:<CN>` at
  tunnel-open.
- **Admin user management, lockout management, emergency lockdown**
  (`POST /admin/lockdown` — all logins 403, all sessions revoked),
  **audit export** (`GET /admin/audit/export?format=json|csv`),
  **Prometheus metrics** (`GET /metrics/prometheus`), **service accounts**
  (`POST /admin/service-accounts`, `POST /auth/service`), a
  **dashboard-auth flag** (`AEGISX_DASHBOARD_AUTH=1`), PEP reachability in
  the dashboard feed, and a **PEP readiness gate**
  (`AEGISX_PEP_REQUIRE_READY=1`).

The full idea list — what shipped, what was deliberately deferred, and what
is proposed next — is in [docs/feature-ideas.md](docs/feature-ideas.md).

## Quick start

**Option A — Docker** (needs Docker; brings its own Redis):

```bash
docker compose up
```

**Option B — local** (needs Python 3.12, Java 17+, Maven, Redis on :6379):

```bash
python3 -m venv .venv
.venv/bin/pip install -r control-plane/requirements.txt
redis-server --port 6379 --save "" --appendonly no --daemonize yes
./scripts/run_all.sh   # builds the PEP jar, starts target + PDP + PEP
```

Then open the dashboard: **http://127.0.0.1:8000/** — an explainer plus a
live demo (login, probe the gateway, watch Redis keys, revoke a session).
`/docs` is the Swagger UI for the raw API.

## Demo walkthrough

Demo users (from `control-plane/app/identity.py` — demo-only passwords):

| User | Password | Role | Entitled app |
|---|---|---|---|
| `alice` | `alice-dev-pw` | developer | `internal-api` (:8080) |
| `bob` | `bob-analyst-pw` | analyst | `metrics-dashboard` (:9090) |
| `admin` | `admin-console-pw` | admin | none — admin console only |

```bash
# 1. Cloak: unauthenticated, the gateway is silent
curl -v http://127.0.0.1:9000/          # -> "Empty reply from server"

# 2. Authenticate alice (session binds to the socket address; see note below)
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# 3. The micro-tunnel exists now -- same client reaches the protected app
curl http://127.0.0.1:9000/hello
# -> {"service": "aegisx-demo-target", "path": "/hello", "peer": "127.0.0.1", "port": 8080}
curl -s -X POST http://127.0.0.1:8000/demo/probe -H 'Content-Type: application/json' -d '{}'
# -> {"allowed":true, ... "detail":"proxied through the authorized micro-tunnel: HTTP/1.0 200 OK"}

# 4. Policy engine: ask for an app you are not entitled to
curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw","app":"metrics-dashboard"}'
# -> 403 "not entitled to application: metrics-dashboard" (no route written)

# 5. Revoke: denylist the JWT + delete the route, atomically
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/logout
# -> {"status":"revoked","jti":"..."}
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/verify  # -> 401
curl http://127.0.0.1:9000/               # -> dropped again (cloak restored)
```

A login is bound to the socket's real peer address. `X-Forwarded-For` is
believed only behind a trusted reverse proxy (`AEGISX_TRUST_PROXY=1`).
`/health` answers after a Redis ping; `/ready` is 200 only when Redis pings
OK *and* the user directory is seeded, else 503.

Prefer a scripted run? `./scripts/demo_e2e.sh` proves it end to end —
cloak → policy → tunnel → **an already-open tunnel killed by revocation** →
cloak — and ends with `ALL CHECKS PASSED`. A 5-minute spoken version is in
[docs/demo-script.md](docs/demo-script.md).

## Certificate identity (mTLS)

With mTLS the tunnel is keyed on the **verified certificate Common Name**,
not the source address: `route:device:alice`, never `route:<client_ip>`.
Two processes on one host can no longer share a tunnel.

```bash
./scripts/gen_certs.sh          # CA + PEP cert + one client cert per identity
CP_PORT=8010 PEP_PORT=9011 ./scripts/demo_mtls.sh   # -> ALL MTLS CHECKS PASSED
```

That script proves it from the same IP: no certificate → rejected at the
handshake; alice's certificate → her app; bob's certificate → denied.
Enroll a new device with `./scripts/enroll_device.sh <CN> <user>` (mints
the cert and registers it); revoke one with
`POST /admin/devices/revoke`, which also kills the device's live sessions.
Details in [docs/design-notes.md](docs/design-notes.md).

## Tests

```bash
(cd control-plane && ../.venv/bin/python -m pytest tests/ -q)   # needs Redis
(cd data-plane && mvn -B package)                               # builds the jar
node --check control-plane/app/static/app.js                    # dashboard JS
./scripts/demo_e2e.sh           # live stack: cloak, policy, tunnel, revoke
./scripts/demo_mtls.sh          # certificate identity
python3 scripts/loadtest_pep.py # accept-to-close latency of the live PEP
```

CI runs all three checks on every push/PR (`.github/workflows/ci.yml`).

## Limitations (honest)

- **Demo PKI** — `certs/` is throwaway material; `ca.key` is in the clear.
- **`/dashboard/state` is unauthenticated by default**, so the demo page works
  with no setup. Set `AEGISX_DASHBOARD_AUTH=1` and it redacts sensitive
  fields unless the request carries an admin token. It must sit behind
  admin auth in any real deployment.
- **Single Redis** is a SPOF. The PEP fails closed, so an outage means a
  global lockout, not a breach — but still a lockout.
- **Revalidation polls** every 5 s, so a revoked tunnel can live up to one
  interval after revocation.
- **`AEGISX_JWT_SECRET` defaults to a dev value** — override it anywhere else.
- The Redis user directory replaces a real IdP (the seam is one function:
  `identity.verify_credentials`).

The full list, with the NIST SP 800-207 mapping and design decisions, is in
[docs/architecture.md](docs/architecture.md) and
[docs/design-notes.md](docs/design-notes.md).

## Layout

| Path | What it is |
|---|---|
| `control-plane/app/` | FastAPI PDP: `routes_auth.py`, `routes_admin.py`, `routes_policy.py`, `routes_demo.py`, `routes_health.py`; `identity.py` (policy + directory), `state.py` (Redis keys + Lua) |
| `control-plane/app/static/` | Dashboard UI: `index.html` + `style.css` + `app.js`, served at `/` |
| `data-plane/src/` | Netty PEP: `ZtnaProxyServer` (bootstrap) + `ZtnaAuthHandler` (the bouncer) |
| `examples/target_service.py` | Stand-in protected app (`--hold` keeps connections open) |
| `scripts/` | `demo_e2e.sh`, `demo_mtls.sh`, `gen_certs.sh`, `run_all.sh`, `enroll_device.sh`, `loadtest_pep.py` |
| `docs/` | `architecture.md`, `demo-script.md`, `design-notes.md`, `feature-ideas.md` |
| `ROADMAP.md` | Phased plan from this demo toward production |
