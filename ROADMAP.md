# AegisX — implementation roadmap

Where the system is today, and exactly what to build next. Every item below is
scoped to what can actually be built and verified **in this repository, on one
machine** (Python + Java + Redis, no cloud accounts), with the verification
command that proves it works. Phases are ordered so each one is independently
shippable and nothing later has to be undone.

Legend: **✅ done** · **▶ next** · **⏳ later**

---

## Where it stands now

| Capability | Status | Proven by |
|---|---|---|
| Cloaking / default-deny at the PEP (`AUTO_READ=false`, no reply to unauthorized) | ✅ | `demo_e2e.sh` step 1 & 8 |
| Identity, entitlement and device-posture policy at login | ✅ | `tests/test_policy.py`, `demo_e2e.sh` step 2 |
| JWT minting + jti-based revocation + Lua-atomic route provisioning | ✅ | `tests/test_auth.py` |
| **Continuous verification** — already-open tunnels die on revocation | ✅ | `demo_e2e.sh` step 7 (`CLOSED_AFTER=2.0`, `pep.revoke` in audit) |
| Admin plane: live session list, force-revoke, policy view | ✅ | `tests/test_admin.py`, dashboard admin console |
| Audit trail (Redis Stream) written by both planes | ✅ | `tests/test_admin.py`, `demo_e2e.sh` audit dump |
| Metrics from PDP + PEP | ✅ | `/metrics`, dashboard counters |
| Real TCP enforcement probe | ✅ | `tests/test_probe.py`, `/demo/probe` |
| **mTLS** with authorization keyed on the certificate CN (`route:device:<CN>`) | ✅ | `scripts/demo_mtls.sh` (same IP: alice's cert allowed, bob's denied), `tests/test_device_identity.py` |
| Brute-force controls: per-user + per-IP limits, lockout | ✅ | `tests/test_auth.py` (429), `fails:*`/`lock:*` |
| Socket-derived `client_ip` (`X-Forwarded-For` only with `AEGISX_TRUST_PROXY=1`) | ✅ | `routes_auth.py: resolve_client_ip` (rework, Nov 2026) |
| Docker Compose stack (`redis`, `control-plane`, `pep`, `target`) | ✅ | `docker-compose.yml` (rework, Nov 2026; not runtime-verified) |
| `/ready` readiness endpoint (Redis ping + users seeded) | ✅ | `routes_health.py` (rework, Nov 2026) |
| PEP load-test harness (accept-to-close latency) | ✅ | `scripts/loadtest_pep.py` (rework, Nov 2026) |
| CI: Python tests + Java build + dashboard JS check | ✅ | `.github/workflows/ci.yml` (rework, Nov 2026) |
| **Policy-as-data + hot reload** (Redis `policy:apps`, admin CRUD, dashboard editor) | ✅ | `tests/test_policy_data.py`, `routes_policy.py` (batch 2, Nov 2026) |
| Time rules (`allowed_hours`) + per-app session TTL | ✅ | `tests/test_time_rules.py` (batch 2, Nov 2026) |
| TLS on the control plane (dedicated PDP cert) | ✅ | `run_all.sh --tls`, `curl --cacert certs/ca.crt https://127.0.0.1:8000/health` (batch 2, Nov 2026) |
| Device enrollment + certificate revocation | ✅ | `scripts/enroll_device.sh`, `tests/test_admin_ops.py` (batch 2; PEP-side check live-unverified) |
| Admin user management (create / disable / enable) | ✅ | `tests/test_admin_ops.py` (batch 2, Nov 2026) |
| Lockout management (list / unlock) | ✅ | `tests/test_admin_ops.py`, dashboard admin console (batch 2, Nov 2026) |
| Emergency lockdown (logins 403 + revoke-all) | ✅ | `tests/test_admin_ops.py` (batch 2, Nov 2026) |
| Audit export (JSON / CSV download) | ✅ | `tests/test_admin_ops.py` (batch 2, Nov 2026) |
| Prometheus metrics (`/metrics/prometheus`) | ✅ | `tests/test_prometheus.py` (batch 2, Nov 2026) |
| Dashboard auth flag (`AEGISX_DASHBOARD_AUTH=1`) | ✅ | `tests/test_dashboard_auth.py` (batch 2, Nov 2026) |
| PEP reachability in the dashboard feed | ✅ | `tests/test_pep_reachable.py` (batch 2, Nov 2026) |
| PEP readiness gate (`AEGISX_PEP_REQUIRE_READY=1`) | ✅ | `ZtnaProxyServer.java` (batch 2; live-unverified — Java TCP blocked in the build VM) |
| Service accounts (API key → JWT, `role=service`) | ✅ | `tests/test_service_accounts.py` (batch 2 stretch, Nov 2026) |

What it is *not* yet: a single-machine demo topology. It is a real enforcement
path with real policy, real revocation and real cryptographic identity — but it
runs one control plane, one PEP and one Redis on one host.

**Done in this rework (Nov 2026):** socket-derived `client_ip` with the
trust-proxy rule (1.1), the Docker Compose stack (2.1), the `/ready` endpoint
(2.2, endpoint only — the PEP is not yet gated on it at startup), the PEP
load-test harness (2.3, without the blocking-Jedis comparison, which was
deliberately not built), and CI (no roadmap item existed for it). See the
marked items below.

**Done in batch 2 (Nov 2026):** policy-as-data + hot reload (3.1), time
rules + per-app TTL (3.2, slim — `allowed_hours` and `session_ttl_seconds`
only; `require_mfa` and the risk score are still open), TLS on the control
plane (1.3), device enrollment + certificate revocation (1.2b), the PEP
readiness gate (2.2, PEP side), and Prometheus metrics export (Phase 4
"Structured metrics export"). Plus items with no roadmap number: admin user
management, lockout management, emergency lockdown, audit export, the
dashboard-auth flag, PEP reachability in the dashboard feed, and service
accounts (stretch). The PEP-side pieces (cert-revocation check, readiness
gate) are **live-unverified** — Java TCP is blocked in the build VM, so
verify them on a real machine. See the marked items below.

---

## Phase 1 ▶ — Identity that survives contact with reality (1–2 days)

Everything here removes the demo shortcuts that a security reviewer will flag
first. None of it needs new infrastructure.

### 1.1 Derive `client_ip` from the socket, not the payload — ✅ done
`client_ip` in the login body is a demo shortcut. Bind the login to the real
source address and make the payload field developer-only.
- **Done in this rework (Nov 2026)**: `routes_auth.py: resolve_client_ip` —
  socket IP by default; `X-Forwarded-For` (first entry) only when
  `AEGISX_TRUST_PROXY=1`, falling back to the payload value when no header is
  present so tests can simulate a proxy.
- **Files**: `control-plane/app/main.py`, `schemas.py`, `tests/test_auth.py`
- **Approach**: use `request.client.host` always; keep an override behind
  `AEGISX_TRUST_PROXY=1` that reads `X-Forwarded-For` from trusted hops only.
- **Verify**: a test that sends a spoofed `client_ip` and asserts the route key
  is written for the socket address instead.
- **Why it still matters after 1.2**: a spoofed `client_ip` no longer buys
data-plane access while the PEP enforces mTLS (authorization is keyed on the
certificate, not the address), but it still pollutes the audit trail and the
per-IP rate limiter, which are keyed on it.

### 1.2 Map the client certificate to the identity (not the IP) — ✅ done
Authorization is keyed on the **verified certificate CN** whenever one is
present; the source address is only the identity for plaintext sessions.
- **Implemented**: login asserts a `device` that must equal the CN registered to
  that identity (`identity.device_matches`); the route and session are written
  under `device:<CN>`; the PEP looks up `route:device:<CN>` and never falls back
  to the address when a certificate was verified; a certificate with no CN is
  refused; both planes audit the CN.
- **Proven**: `scripts/demo_mtls.sh` opens three connections *from the same IP*
  — no certificate (rejected), alice's certificate (allowed), bob's certificate
  (denied, `no-device-route` in the audit) — plus a 403 when alice tries to
  assert bob's identity; unit coverage in `tests/test_device_identity.py`.
- **Still open (1.2b)**: certificate registration is seeded demo data. A real
deployment needs a signed enrollment/registration step (admin API, or the IdP
issuing the certificate at provisioning time) plus revocation of a compromised
certificate itself, not only of the sessions it opened.
- **Done in batch 2 (Nov 2026) (1.2b)**: `POST /admin/devices` registers a
  CN to a user; `scripts/enroll_device.sh <CN> <user>` mints the client
  certificate (demo CA, 825-day default) and registers it in one step;
  `POST /admin/devices/revoke` writes `cert:deny:<CN>` (24 h TTL) and
  revokes the CN's live sessions; the PEP checks `cert:deny` at tunnel-open
  (`ZtnaAuthHandler.checkCertNotRevoked`, async, fail-closed) and the login
  path rejects a revoked cert with 403 before provisioning a route. The
  24 h TTL is a demo CRL, not a real one — a production deployment needs a
  persistent revocation list, because the entry expires and the certificate
  would work again. **Live-unverified**: the PEP-side check needs
  `scripts/demo_mtls.sh` plus a revoked cert on a real machine.
  Worth noting that the
model shifts the trust anchor to *key custody*: whoever can read a client key
can act as that identity, so key protection (agent, keychain, TPM) becomes part
of the security story rather than an implementation detail.
- **Free win**: a session is now portable across network changes — the tunnel is
  bound to the certificate, so a new source address does not break (or leak) it.

### 1.3 TLS on the control plane — ✅ done
The PDP is plain HTTP today. Add HTTPS with the same demo CA.
- **Done in batch 2 (Nov 2026)**: dedicated PDP server certificate
  (`certs/pdp.crt`, CN `localhost`, SANs `localhost`/`127.0.0.1`) from
  `scripts/gen_certs.sh`; `./scripts/run_all.sh --tls` or `AEGISX_TLS=1`
  serves the PDP over HTTPS (uvicorn `--ssl-keyfile/--ssl-certfile`).
  Plain HTTP stays the default, and the script refuses TLS mode early with
  a clear hint if the PDP certificate is missing.
- **Files**: `ZtnaProxyServer`-style SslContext is not needed; run uvicorn with
  `--ssl-keyfile/--ssl-certfile` (or terminate TLS in the deployment layer).
- **Verify**: `curl --cacert certs/ca.crt https://127.0.0.1:8000/health`.

---

## Phase 2 ▶ — Operations: make it runnable by someone else (1–2 days)

### 2.1 Docker Compose stack — ✅ done
`redis`, `control-plane`, `pep`, and a `target` service in one `compose up`,
with healthchecks and the cert volume mounted read-only.
- **Done in this rework (Nov 2026)**: `docker-compose.yml` + Dockerfiles for
  all four services (`control-plane/Dockerfile`, `data-plane/Dockerfile`,
  `examples/Dockerfile`). Two deviations from the plan: the target shares the
  PEP's network namespace (`network_mode: "service:pep"`) because
  `APP_TARGETS` hardcodes `127.0.0.1:8080`; and no cert volume is mounted —
  compose runs the plaintext demo, so mTLS wiring is still to come.
  Not runtime-verified (no Docker in the build VM).
- **Files**: `deploy/Dockerfile.control-plane`, `deploy/Dockerfile.pep`, `docker-compose.yml`
- **Verify**: `docker compose up -d && ./scripts/demo_e2e.sh` against the
  published ports. This also gives a laptop-independent reproduction path.

### 2.2 Readiness and liveness endpoints — ✅ done
`/health` is a single flat check today. Add `/ready` (Redis reachable **and**
user directory seeded) and point the PEP at it at startup so it refuses to
serve until it can read state.
- **Done in this rework (Nov 2026)**: `/ready` in `routes_health.py` — 200
  `{"status": "ready"}` only when Redis pings OK and at least one `users:*`
  record exists, else 503. Not done: pointing the PEP at it at startup (the
  PEP still starts regardless; it fails closed per-connection instead).
- **Done in batch 2 (Nov 2026)**: the PEP gate —
  `AEGISX_PEP_REQUIRE_READY=1` makes `ZtnaProxyServer` poll the PDP's
  `/ready` (default `http://127.0.0.1:8000`, 10 attempts, 1–5 s backoff)
  before binding, and exit(1) without listening if the PDP never reports
  ready. Default off, so startup is unchanged unless the flag is set.
  **Live-unverified**: Java TCP is blocked in the build VM — verify by
  starting the PEP with Redis down and the flag on, on a real machine.
- **Files**: `main.py`, `ZtnaProxyServer.java`
- **Verify**: a test that stops Redis and asserts `/ready` → 503 while `/health`
  still answers, plus a PEP test that starts with Redis down and refuses traffic.

### 2.3 Load test: prove the non-blocking claim (this is the report's thesis) — ✅ done (harness only)
Ship a harness that hammers the PEP with concurrent unauthorized connections and
measures EventLoop responsiveness, then *reproduce the anti-pattern* by swapping
Lettuce for a blocking Jedis lookup behind a flag.
- **Done in this rework (Nov 2026)**: `scripts/loadtest_pep.py` (stdlib only)
  measures accept-to-close latency (p50/p99/mean, connections/sec) against the
  real non-blocking PEP. Deliberately NOT built: the blocking-Jedis comparison
  variant — the anti-pattern stays out of the codebase, so the README table
  comparing both modes does not exist either.
- **Files**: `scripts/loadtest_pep.py`, `ZtnaAuthHandler.java` (`AEGISX_BLOCKING_REDIS=1` for the comparison only)
- **Verify**: a table in the README: p50/p99 accept-to-close latency and
  throughput for both modes at 200/1000/5000 concurrent connections, showing
  Lettuce holding steady and the blocking variant collapsing. Numbers, not
  adjectives.

### 2.4 Multi-client topology
Run two PEPs (edge + app-side) or a PEP per app so the demo stops collapsing
every role onto `127.0.0.1`. Needed to show real segmentation.
- **Verify**: two routes from two source IPs reach two different apps, and a
  third source reaches neither.

---

## Phase 3 ⏳ — Policy depth (2–4 days)

### 3.1 Policy as data, not Python constants — ✅ done
Move `APP_TARGETS` / `POSTURE_RULES` into Redis (`policy:apps`) with an admin
write API, hot-reloaded by the PDP on change (and optionally by the PEP for
per-app rules).
- **Done in batch 2 (Nov 2026)**: the live policy is the Redis hash
  `policy:apps` (one JSON record per app: `target`, `posture`,
  `allowed_hours`, `session_ttl_seconds`, `enabled`); `APP_TARGETS` /
  `POSTURE_RULES` are now only the seed defaults, and `policy:seeded` stops
  the seed resurrecting a deleted app. `GET/PUT/DELETE /admin/policy`
  (`routes_policy.py`) edits it, a dashboard policy editor sits in the
  admin console, and every write invalidates the 5 s in-memory cache
  (`identity.invalidate_policy_cache`), so the next login is judged by the
  new rules with no restart. The PEP does not read policy — it only ever
  sees the route the PDP wrote, so no PEP hot-reload was needed.
- **Files**: `identity.py`, new `admin` endpoints, dashboard policy editor.
- **Verify**: change a posture rule through the API and show the next login
  flipping from 200 to 403 with no restart. (`tests/test_policy_data.py`)

### 3.2 Time, location and risk signals — ✅ done (slim)
Add `allowed_hours`, per-app `require_mfa`, and a simple risk score that
downgrades a session (shorter TTL) instead of hard-denying.
- **Done in batch 2 (Nov 2026) (slim)**: `allowed_hours` (`"HH:MM-HH:MM"`,
  same-day only, empty = always) denies logins outside the window with a
  message naming the window, and per-app `session_ttl_seconds` (60–86400)
  sets the route + session lifetime — the short-TTL half of the "downgrade
  instead of deny" idea, minus the risk score. Still open: `require_mfa`
  (see `docs/feature-ideas.md` idea 26, TOTP) and the risk score itself.
- **Verify**: table-driven tests per rule, plus a demo where the same identity
  gets a 60-second tunnel outside business hours. (`tests/test_time_rules.py`:
  set `session_ttl_seconds: 60` on an app and the route TTL is 60 s.)

### 3.3 Real IdP instead of the Redis directory
Swap `identity.verify_credentials` for an OIDC authorization-code flow, keeping
the users table as a fallback for tests. The seam already exists
(`users:<name>` hashes, one function).
- **Verify**: log in against a local Keycloak/Dex container and assert the JWT
  carries the IdP's `sub` and group claims.

### 3.4 Per-app protocol awareness
The PEP is L4. Add a sniffing mode that allows only the protocols an entitlement
permits (e.g. HTTP/1.1 or Postgres wire), so a tunnel to `internal-api` can't be
used for SSH on that port.
- **Verify**: send SSH bytes through an HTTP-only entitlement and assert the
  connection is closed mid-stream.

---

## Phase 4 ⏳ — Scale, resilience, and the report's stretch items

| Item | Why | Note |
|---|---|---|
| Redis Sentinel/Cluster mode | Single Redis is a SPOF; the PEP fails closed, so an outage means a global lockout | Lua scripts are already atomic; key schema is cluster-friendly except `sess:*` scans (use a set index) |
| Multiple PDP instances | Horizontal scale for login bursts | Requires moving rate-limit state fully into Redis (already there) and a shared JWT secret |
| Session revocation bus | Peers learn about revocations immediately instead of on the next poll | Redis pub/sub → PEP closes the tunnel within milliseconds; keep polling as the safety net |
| SPIFFE/SPIRE workload identity | Identity for services, not only humans | Replaces static certs with short-lived SVIDs, ideally the next step after 1.2 |
| eBPF/XDP default-drop | Move the deny decision into the NIC driver for line-rate DDoS immunity | The report's headline stretch goal; needs a Linux host, so it is deliberately out of scope for this macOS demo |
| Structured metrics export | `/metrics` is JSON today | ✅ done in batch 2 (Nov 2026): `GET /metrics/prometheus` emits the same counters in Prometheus text format, plus an uptime gauge (`tests/test_prometheus.py`) |

---

## Deliberate non-goals (kept out on purpose)

- **No PKI for real users** — `certs/` is throwaway demo material; `ca.key` must
  never leave a test machine.
- **No WAF/DPI** — AegisX enforces *who* and *whether*, not payload inspection.
- **No Kubernetes/Helm** — Compose is enough to reproduce and review; cluster
  packaging belongs with the deployment story, not the reference implementation.
- **No UI framework rewrite** — the dashboard is three plain files (HTML +
  CSS + JS) on purpose: it must run with zero build step so a reviewer can
  read the request flow end-to-end.

---

## How to verify the whole thing after any change

```bash
redis-cli ping                                 # state store up
(cd control-plane && ../.venv/bin/python -m pytest tests/ -q)   # 107 tests passing (13 Nov 2026)
./scripts/demo_e2e.sh                          # cloak → policy → tunnel → revoke → live-tunnel kill
./scripts/demo_mtls.sh                         # certificate required, CN audited
```

If those four are green, the enforcement path, the policy engine, the audit
trail and the cryptographic identity are all intact.
