# AegisX — Identity-Aware Zero Trust Network Access Gateway

A reference implementation of the architecture described in the accompanying
research report: an Identity-Aware ZTNA gateway that replaces implicit-trust
VPNs with **Authenticate-Before-Connect** access, strictly separating the
**Control Plane** (policy decisions) from the **Data Plane** (packet routing).

```
                            ┌──────────────────────────────────────────────────┐
   POST /auth/login         │  CONTROL PLANE — Policy Decision Point (PDP)     │
  ───────────────────────►  │  Python 3 / FastAPI                              │
   {user, pass, app,        │   ├─ Policy Engine:     verify creds, entitlement │
    posture}                │   │                     device posture, mint JWT │
                            │   ├─ Policy Admin:      Lua-atomic provisioning,  │
                            │   │                     sessions, force-revoke    │
                            │   └─ Policy Info Point: users:<name> directory    │
                            └───────────────┬──────────────────────────────────┘
                                            │ SET route:<binding> = host:port   EX 3600
                                            │     binding = device:<cert CN> | source address
                                            │ SET jwt:deny:<jti>       (revocation)
                                            │ XADD audit:events        (every decision)
                                            ▼
                                   ┌─────────────────┐
                                   │  Redis 8        │  ephemeral state broker
                                   │  (state store)  │  sub-ms reads/writes
                                   └────────┬────────┘
                                            │ GET route:<binding>     (async, Lettuce)
                                            │ + re-read every 5 s     (revalidation)
                                            ▼
   TCP / mTLS connect     ┌──────────────────────────────────────────────────┐
  ───────────────────────►│  DATA PLANE — Policy Enforcement Point (PEP)     │
   (any client)           │  Java 17+ / Netty                                │
                          │   ├─ no client cert  → TLS handshake rejected    │
                          │   ├─ cert without CN → refused (not keyed on IP) │
                          │   ├─ no route record → ctx.close()   (cloak)     │
                          │   ├─ route record    → L4 tunnel to one target   │
                          │   └─ even mid-transfer failures: INCR pep:*,     │
                          │      XADD audit:events                           │
                          └───────────────┬──────────────────────────────────┘
                                          │ authorized micro-tunnel only,
                                          │ torn down within one revalidation
                                          │ interval of session loss
                                          ▼
                                  protected internal app
```

## The dashboard

`GET /` serves a self-contained explainer + live-demo UI
([control-plane/app/static/index.html](control-plane/app/static/index.html)) —
plain-language "what is this / how it works" sections plus an interactive demo
that drives the real servers:

- **Identify & authorize** — pick an identity, the app you are asking for, and
  your device-posture claims. Denials (403 entitlement, 403 posture, 429 rate
  limit, 423 lockout) are shown as the policy engine produces them.
- **Probe the gateway** — `POST /demo/probe` opens a *real TCP connection* to
  the PEP and reports what the gate decided (ALLOW with the tunnel target, or
  the cloak: accepted then closed with no payload).
- **Enforcement counters** — allow / deny / revoked-mid-flow / open tunnels /
  logins / admin revocations, read from `/metrics`.
- **Redis inspector + session table** — the exact keys the Netty PEP consults
  (`route:*`, `sess:*`, `jwt:deny:*`, `login:rl:*`, `ipl:*`, `lock:*`) with live
  TTL bars, plus the PDP's joined view of every live tunnel.
- **Audit trail** — the append-only `audit:events` stream rendered as it grows.
- **Admin console** — authenticate as `admin`, list live sessions from
  `/admin/sessions`, and force-revoke one from the UI; `/admin/revoke` denylists
  that session's token and deletes its route, so the PEP kills the open tunnel
  on its next revalidation.

`GET /dashboard/state` (demo-only, unauthenticated — see security notes) feeds
the live view. `/docs` remains the Swagger UI for the raw API.

## Certificate identity: the tunnel belongs to a key, not an address

`client_ip` alone is a weak identity: every process on a host shares it. When
the PEP runs with mTLS the authorization identity becomes the **verified
certificate Common Name**, and the source address stops being an
authorization key at all:

```
login  -> device "alice" is registered to alice  -> route:device:alice = host:port
                                             (no route:<client_ip> is written)
PEP    -> verifies client certificate -> looks up route:device:<CN>
          no certificate       -> TLS handshake rejected
          certificate without CN -> refused
          CN with no route     -> DENY, audited as no-device-route
```

A login may therefore only assert the `device` registered to it (claiming
someone else's is a 403, audited), and two processes on one host no longer
share a tunnel: possession of the certificate is the entitlement.

```bash
./scripts/gen_certs.sh          # CA + PEP cert + one client cert per identity
CP_PORT=8010 PEP_PORT=9011 ./scripts/demo_mtls.sh
```

That script proves it with three connections **from the same IP 127.0.0.1**:
no certificate → rejected at the handshake; alice's certificate → ALLOW, proxied
to her entitled app; bob's certificate → DENY (cloak). Alice asserting bob's
identity at login is refused. Both planes audit the CN, and the same check is
available from the dashboard (choose the certificate to present, then probe).

## Repository layout

| Path | Component |
|---|---|
| [control-plane/](control-plane/) | FastAPI PDP: `/auth/login`, `/auth/logout`, `/auth/verify`, JWT minting, Redis denylist, Lua-atomic state changes |
| [control-plane/app/config.py](control-plane/app/config.py) | All tunables (TTLs, rate limits, lockout, posture strictness, probe address) |
| [control-plane/app/identity.py](control-plane/app/identity.py) | Policy Information Point: Redis user directory + entitlement/posture rules |
| [control-plane/app/state.py](control-plane/app/state.py) | Redis key schema, the two embedded Lua scripts, audit stream, metrics, sessions |
| [data-plane/](data-plane/) | Netty PEP: `ZtnaAuthHandler` zero-trust bouncer, async Lettuce lookup, continuous revalidation, optional mTLS, L4 reverse proxy |
| [control-plane/app/static/index.html](control-plane/app/static/index.html) | Dashboard UI: explainer + interactive demo + admin console, served at `/` |
| [examples/target_service.py](examples/target_service.py) | Stand-in protected application (`--hold` keeps a connection open for the revocation proof) |
| [scripts/demo_e2e.sh](scripts/demo_e2e.sh) | End-to-end proof: cloak → policy → tunnel → **live-tunnel revocation** → cloak |
| [scripts/demo_mtls.sh](scripts/demo_mtls.sh) | mTLS proof: no client cert → rejected; valid cert → tunneled, CN audited |
| [scripts/gen_certs.sh](scripts/gen_certs.sh) | Local PKI (CA + PEP server cert + per-identity client certs) |
| [ROADMAP.md](ROADMAP.md) | Phased plan from this reference implementation to production |

## Mapping to NIST SP 800-207 / CSA SDP

| NIST SP 800-207 role | AegisX implementation |
|---|---|
| Policy Decision Point (PDP) | FastAPI control plane |
| Policy Engine (PE) | `POST /auth/login`: credential check, entitlement resolution, device-posture evaluation, JWT minting |
| Policy Administrator (PA) | Lua-atomic `route:<client_ip>` provisioning / teardown, `/admin/sessions`, `/admin/revoke` |
| Policy Information Point (PIP) | `users:<name>` directory in Redis ([identity.py](control-plane/app/identity.py)), the seam for an OIDC/LDAP connector |
| Policy Enforcement Point (PEP) | Netty `ZtnaAuthHandler`; **default-deny**, no autonomous trust decisions |
| Continuous verification | PEP re-reads the route every `AEGISX_REVALIDATE_SECONDS` (default 5) and closes tunnels whose session no longer exists |
| Authorization identity (binding) | `device:<cert CN>` when a client certificate is verified, otherwise the source address ([state.py](control-plane/app/state.py)); the address is never consulted for a certificate-bound session |

CSA SDP behaviors realized: *Authenticate-Before-Connect* (`AUTO_READ=false`
until the Redis route record authorizes the source IP, and no backend connect
before authorization even when mTLS requires reads), *resource cloaking*
(unauthorized connections are closed with no application-layer response), and
*connection-defined segmentation* (one identity → one `host:port`
micro-tunnel with a 3600 s TTL, not a subnet).

## Quick start

Prerequisites: Python 3.9+, Java 17+ (tested on 26), Maven, Redis.

```bash
# 1. Python env
python3 -m venv .venv
.venv/bin/pip install -r control-plane/requirements.txt

# 2. Redis (any local instance; no auth needed for the demo)
redis-server --port 6379 --save "" --appendonly no --daemonize yes

# 3. Build the PEP
(cd data-plane && mvn package)

# 4. Local PKI for the mTLS demo (writes certs/, throwaway material)
./scripts/gen_certs.sh

# 5. Run the automated end-to-end demo
./scripts/demo_e2e.sh

# 6. (optional) prove mTLS enforcement + certificate identity
./scripts/demo_mtls.sh
```

`demo_e2e.sh` ends with `ALL CHECKS PASSED`: cloaking before login, policy
denials that create no route, route provisioning with TTL, bytes proxied
through the tunnel, a real TCP probe through the gate, token verification,
**an already-open tunnel being killed by continuous verification**, and
cloaking restored. `demo_mtls.sh` ends with `ALL MTLS CHECKS PASSED`: a client
without a certificate is rejected at the handshake, a certificate signed by the
demo CA is tunneled, and the certificate's Common Name is what the audit trail
records as the device identity.

Both scripts take `CP_PORT` / `PEP_PORT` / `TARGET_PORT` overrides, so they can
run alongside a control plane you already have on :8000.

### Manual walkthrough

```bash
# terminals
(cd control-plane && ../.venv/bin/python -m uvicorn app.main:app --port 8000)
java --enable-native-access=ALL-UNNAMED -jar data-plane/target/aegisx-ztna-proxy.jar   # :9000
.venv/bin/python examples/target_service.py --port 8080

# unauthenticated: silently dropped
curl -v http://127.0.0.1:9000/            # -> "Empty reply from server"

# authenticate (demo users: alice/alice-dev-pw, bob/bob-analyst-pw)
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw","client_ip":"127.0.0.1"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# now the micro-tunnel exists
curl http://127.0.0.1:9000/hello          # -> response from the target app
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/verify

# revoke: denylist JWT + delete route -> cloak restored instantly
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/logout
curl http://127.0.0.1:9000/               # -> dropped again

# policy engine: ask for an app you are not entitled to
curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw","client_ip":"127.0.0.1","app":"metrics-dashboard"}'
# -> 403 "not entitled to application: metrics-dashboard" (no route written)

# policy engine: report a failing posture claim
curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw","client_ip":"127.0.0.1","posture":{"disk_encrypted":false}}'
# -> 403 "device posture denied: disk_encrypted: expected True, got False"

# real enforcement probe: opens a TCP connection to the PEP and reports the verdict
curl -s -X POST http://127.0.0.1:8000/demo/probe -H 'Content-Type: application/json' -d '{}'

# metrics + the live session view (admin role required)
curl -s http://127.0.0.1:8000/metrics
ADMIN=$(curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin-console-pw","client_ip":"127.0.0.1"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $ADMIN" http://127.0.0.1:8000/admin/sessions
curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"client_ip":"127.0.0.1","reason":"incident"}' http://127.0.0.1:8000/admin/revoke
curl -s -H "Authorization: Bearer $ADMIN" http://127.0.0.1:8000/admin/audit
```

## Key design decisions (per the report)

**JWT revocation — denylist, not allowlist.** Only *revoked* jtis occupy
memory (`jwt:deny:<jti>`), and each entry's TTL mirrors the token's remaining
`exp`, so Redis prunes entries by itself the moment the token would die
anyway. Pair with `maxmemory-policy volatile-ttl` in production `redis.conf`.
`/auth/logout` also deletes the PEP's route key in the same Lua script, so
control-plane revocation and data-plane revocation are one atomic step.

**Lua for atomicity.** Two embedded scripts ([state.py](control-plane/app/state.py)):
the login gate (rate-limit accounting + route provisioning) and revocation
(denylist write + route teardown). No distributed locks; concurrent control
plane instances cannot interleave a login against a logout.

**Fail closed.** Any Redis error in the PEP closes the client connection.
A state-store outage narrows access; it never widens it.

**Non-blocking data plane.** The report's central critique — blocking Jedis
inside `channelActive` starves Netty EventLoops — is avoided by construction:
Lettuce's `RedisFuture` callback hops back onto the channel's own EventLoop
before touching the pipeline. The client channel keeps `AUTO_READ=false`
until authorization, so pre-auth bytes never enter application memory.

## Tests

```bash
(cd control-plane && ../.venv/bin/python -m pytest tests/ -q)   # 47 tests
./scripts/demo_e2e.sh                                          # live stack
./scripts/demo_mtls.sh                                         # certificate identity
```

| File | Covers |
|---|---|
| [test_auth.py](control-plane/tests/test_auth.py) | route provisioning + TTL, 401s for bad credentials / forged signatures, rate-limit 429s, logout revoking both the token and the route key |
| [test_policy.py](control-plane/tests/test_policy.py) | entitlement per identity, cross-app 403, unknown app 404, posture pass/fail, admin identities getting no tunnel, admin endpoints rejecting non-admins |
| [test_admin.py](control-plane/tests/test_admin.py) | live session listing, force-revoke killing a session whose token is still valid, audit stream contents, metrics counters |
| [test_probe.py](control-plane/tests/test_probe.py) | `/demo/probe` really speaks TCP: ALLOW against an answering listener, cloak against a listener that closes with no payload, unreachable gateway |
| [test_device_identity.py](control-plane/tests/test_device_identity.py) | certificate binding: device-keyed route with no IP route, 403 when claiming another identity's certificate, revoke by binding, sessions/state exposing the CN, probe presenting a certificate, path-traversal guard on certificate names |
| [test_dashboard.py](control-plane/tests/test_dashboard.py) | the page is served with its demo hooks, the state feed tracks login/session/audit/revocation, the device controls are present, and the inline JavaScript actually parses (`node --check`, skipped if node is absent) |

Requires a reachable Redis; the suite clears every AegisX-namespaced key
(`route:`, `sess:`, `jwt:deny:`, `login:rl:`, `ipl:`, `fails:`, `lock:`,
counters, `audit:events`) before each test so it never touches unrelated data.

## Security notes & deliberate simplifications

- **Client-supplied `client_ip`** in the login payload is a demo shortcut (the
  report notes production must derive it from the request socket / trusted
  proxy headers). It is no longer an authorization key when the PEP enforces
  mTLS, but it is still what the audit trail and the per-IP rate limiter record,
  so spoofing it pollutes logs instead of granting access.
- **Localhost demo topology** collapses all roles onto one IP. That is exactly
  what certificate binding fixes: with mTLS the tunnel is keyed on the
  certificate CN, so another process on the same host — or the same host with a
  different credential — gets nothing. What mTLS does *not* fix is key custody:
  whoever can read a client's private key can act as that identity, and the
  demo keys live unencrypted in `certs/`.
- **Certificate registration is seeded demo data** (`device` on the user
  record). A production deployment needs an authorized enrollment step and
  certificate revocation, not just session revocation — see
  [ROADMAP.md](ROADMAP.md) item 1.2b.
- **`/dashboard/state` is unauthenticated** on purpose so the explainer page
  works with no setup. It exposes operational topology (session identities, audit
  events) and must sit behind admin auth in any real deployment; `/admin/*`
  already requires an `admin`-role token.
- **The Redis user directory** replaces a real IdP; swap
  `identity.verify_credentials` for an OIDC token/introspection call — the rest
  of the pipeline is unchanged.
- **The `certs/` directory is throwaway demo material.** `gen_certs.sh` writes
  `ca.key` in the clear; never use these certificates outside a test machine.
- **Single Redis** is a SPOF: because the PEP fails closed, a state-store outage
  means a global lockout rather than a breach. Production uses Sentinel/Cluster.
- `AEGISX_JWT_SECRET` defaults to a dev value and must be overridden.
- **Revalidation is polling** (`AEGISX_REVALIDATE_SECONDS`, default 5). A
  Redis pub/sub revocation bus would cut the worst-case window to milliseconds;
  polling stays as the safety net.

## Roadmap

[ROADMAP.md](ROADMAP.md) is the phased plan from this reference implementation
to production: socket-derived client identity, certificate-to-identity binding,
TLS on the control plane, a Docker Compose stack, a load test that measures the
non-blocking claim (and reproduces the blocking-Jedis anti-pattern for
comparison), policy-as-data with hot reload, an OIDC connector, protocol
awareness, and the scale items (Redis Sentinel, multiple PDPs, a revocation bus,
SPIFFE, eBPF/XDP).

Already shipped from that plan: device-posture evaluation, continuous
re-verification of live tunnels, the admin surface with force-revocation, the
audit trail, per-user and per-IP brute-force controls, a real enforcement probe,
and mTLS with authorization keyed on the certificate identity (item 1.2).
