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
- Shipped with 64 passing tests (pytest, incl. mTLS device-identity and
  client-IP spoof-rejection tests), a real-TCP probe endpoint, Docker Compose
  one-command demo, CI (pytest + Maven + `node --check`), and a monochrome
  dashboard showing live routes, sessions and the audit trail.

## Tech line

`Java 17 · Netty 4.2 · Lettuce (async Redis) · Python · FastAPI · Redis + Lua ·
JWT · mTLS (X.509) · Docker Compose · GitHub Actions`

## Numbers you can defend (all true, all checkable)

| Claim | Source |
|---|---|
| 64 tests passing | `cd control-plane && pytest` (13 Nov 2026, after `scripts/gen_certs.sh`) |
| 5 s revalidation interval | `AEGISX_REVALIDATE_SECONDS` default in `ZtnaProxyServer.java` |
| 3600 s route / token TTL | `ROUTE_TTL_SECONDS`, `ACCESS_TOKEN_TTL_SECONDS` in `config.py` |
| Real TCP probe | `POST /demo/probe` opens a live socket (`routes_demo._run_probe`) |
| Lua-atomic login gate + logout | `LOGIN_LUA`, `LOGOUT_LUA` in `state.py` |
| 2 planes, 0 direct calls between them | PDP writes Redis, PEP reads Redis (`docs/architecture.md`) |

## Numbers NOT to claim

- No load-test numbers for the PEP: `scripts/loadtest_pep.py` exists and was
  verified against a stub server, but PEP throughput/latency was never
  measured on a live PEP in this build (the build VM blocks Java TCP). Run it
  yourself against a live stack before quoting any figure.
- No uptime/availability claim: single Redis, no HA — say so if asked.
