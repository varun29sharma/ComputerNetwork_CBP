# RESUME.md — AegisX

## One-line title

**AegisX — Identity-Aware Zero Trust Network Access (ZTNA) Gateway** ·
Python (FastAPI) control plane + Java (Netty) data plane + Redis

## Resume bullets (all numbers verified from this repo)

- Built a zero-trust network access gateway (NIST SP 800-207) in which a
  FastAPI control plane authenticates users and writes one-identity, one-app
  micro-tunnels to Redis, and a non-blocking Netty data plane authorizes each
  TCP connection with a single async Redis lookup — unauthorized clients are
  silently cloaked (connection closed, no payload).
- Implemented continuous verification: every open tunnel is re-validated
  against Redis every 5 s, so revoking a session tears down live tunnels
  within seconds; JWT revocation via a Redis denylist keyed by `jti`, and
  Lua-atomic login/logout so lockout, rate-limit and route writes cannot race.
- Shipped with 107 tests passing (pytest, 13 Nov 2026 — incl. mTLS
  device-identity, client-IP spoof-rejection, policy-as-data, time-rule and
  service-account tests), a real-TCP probe endpoint, Docker Compose
  one-command demo, CI (pytest + Maven + `node --check`), and a monochrome
  dashboard showing live routes, sessions and the audit trail.
- Grew the admin plane in a second batch: policy-as-data with hot reload
  (admin API + dashboard editor, no restart), time windows and per-app
  session TTLs, device enrollment with certificate revocation, user and
  lockout management, a one-switch emergency lockdown, audit export
  (JSON/CSV), Prometheus metrics, TLS on the control plane, and
  service-account API keys (shown once, SHA-256 stored) — all behind the
  same Lua-atomic revoke path, so one switch kills live tunnels within
  seconds.

## Tech line

`Java 17 · Netty 4.2 · Lettuce (async Redis) · Python · FastAPI · Redis + Lua ·
JWT · mTLS (X.509) · Docker Compose · GitHub Actions`

## Numbers you can defend (all true, all checkable)

| Claim | Source |
|---|---|
| 107 tests passing | Full pytest suite, 13 Nov 2026 (107 passed, 0 failed, 0 skipped) |
| 5 s revalidation interval | `AEGISX_REVALIDATE_SECONDS` default in `ZtnaProxyServer.java` |
| 3600 s route / token TTL | `ROUTE_TTL_SECONDS`, `ACCESS_TOKEN_TTL_SECONDS` in `config.py` |
| Per-app session TTL 60–86400 s | `SESSION_TTL_MIN/MAX_SECONDS` in `identity.py` |
| Real TCP probe | `POST /demo/probe` opens a live socket (`routes_demo._run_probe`) |
| Lua-atomic login gate + logout | `LOGIN_LUA`, `LOGOUT_LUA` in `state.py` |
| 2 planes, 0 direct calls between them | PDP writes Redis, PEP reads Redis (`docs/architecture.md`) |

## Numbers NOT to claim

- No load-test numbers for the PEP: `scripts/loadtest_pep.py` exists and was
  verified against a stub server, but PEP throughput/latency was never
  measured on a live PEP in this build (the build VM blocks Java TCP). Run it
  yourself against a live stack before quoting any figure.
- No uptime/availability claim: single Redis, no HA — say so if asked.
- No live verification of the PEP-side batch-2 pieces: the cert-revocation
  check (`checkCertNotRevoked`) and the readiness gate
  (`requireControlPlaneReady`) are implemented and code-reviewed, but Java
  TCP is blocked in the build VM, so they were never observed running.
  Verify with `scripts/demo_mtls.sh` plus a revoked cert, and by starting
  the PEP with Redis down and `AEGISX_PEP_REQUIRE_READY=1`, on a real
  machine before presenting them as proven.
- Test count covers the control plane only: 107 pytest tests, all passing.
  The Java data plane has no test harness — its batch-2 changes are
  compile-checked only (javac), not test-verified.
