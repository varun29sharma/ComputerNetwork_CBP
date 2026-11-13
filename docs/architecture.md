# AegisX architecture

## The picture

```mermaid
flowchart TB
    Client([Client]) -->|1. POST /auth/login| PDP[PDP — FastAPI :8000<br/>Policy Decision Point]
    PDP -->|2. SET route:&lt;binding&gt; = host:port| Redis[(Redis :6379<br/>state broker)]
    Client -->|3. TCP connect| PEP[PEP — Netty :9000<br/>Policy Enforcement Point]
    PEP -->|4. GET route:&lt;binding&gt;| Redis
    PEP -->|5. tunnel, only if a route exists| App[Protected app :8080]
```

Same diagram in plain text (for terminals and READMEs):

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

## The 60-second data flow

**Login.** The client POSTs a username and password to the PDP (`:8000`).
The PDP checks the password against the Redis user directory, checks the
policy — is this identity entitled to that app, does the device posture pass,
is the certificate identity (if any) the one registered to this user — and,
only if everything passes, mints a JWT and writes one record into Redis:
`route:<binding> = host:port`, with a 3600 s TTL. The binding is the
certificate's Common Name (`device:alice`) when a certificate is involved,
otherwise the source address the login came from.

**Route.** That Redis record is the entire authorization. There is no call
from the PDP to the PEP and no config file to reload — the record existing
*is* the permission.

**Tunnel.** The client then opens a TCP connection to the PEP (`:9000`). The
PEP looks up `route:<binding>` in Redis (async, via Lettuce, so no Netty
EventLoop thread ever blocks). No record → the connection is closed with no
payload at all: the gateway looks like a closed port (cloaking). Record →
the PEP opens a micro-tunnel to exactly that one `host:port` and forwards
bytes. While the tunnel is open the PEP re-reads the route every 5 s
(`AEGISX_REVALIDATE_SECONDS`).

**Revoke.** Logout, admin force-revoke, or TTL expiry deletes the route and
denylists the JWT's `jti` in one atomic Lua script. The next revalidation
— at most 5 s later — closes tunnels that are already open, not just future
connections. The token itself is dead immediately: `/auth/verify` answers 401.

## Ports and environment

| Port | Service | Source of the default |
|---|---|---|
| 8000 | PDP (FastAPI) | `scripts/demo_e2e.sh` (`CP_PORT`) |
| 9000 | PEP (Netty) | `AEGISX_PEP_PORT` in `ZtnaProxyServer.java` |
| 8080 | Protected app `internal-api` | `APP_TARGETS` in `identity.py` |
| 9090 | Protected app `metrics-dashboard` | `APP_TARGETS` in `identity.py` |
| 6379 | Redis | `AEGISX_REDIS_URL` in `config.py` |

Key environment variables (all defaults live in `control-plane/app/config.py`
and `ZtnaProxyServer.java`): `AEGISX_REDIS_URL`, `AEGISX_JWT_SECRET`,
`AEGISX_TOKEN_TTL` (3600), `AEGISX_ROUTE_TTL` (3600),
`AEGISX_LOGIN_RATE_LIMIT` (5) / `AEGISX_LOGIN_RATE_WINDOW` (60),
`AEGISX_LOGIN_IP_RATE_LIMIT` (30), `AEGISX_LOGIN_FAIL_MAX` (5),
`AEGISX_LOCKOUT_SECONDS` (300), `AEGISX_POSTURE_STRICT` (0),
`AEGISX_PEP_PROBE_ADDR` (`127.0.0.1:9000`), `AEGISX_PEP_PORT` (9000),
`AEGISX_REVALIDATE_SECONDS` (5), `AEGISX_MTLS` + `AEGISX_MTLS_CERT` /
`AEGISX_MTLS_KEY` / `AEGISX_MTLS_CA`, and `AEGISX_TRUST_PROXY` (0).

**Client identity rule.** A login is bound to the socket's real peer address.
The `client_ip` field in the login body is ignored by default; only behind a
trusted reverse proxy (`AEGISX_TRUST_PROXY=1`) is the first entry of
`X-Forwarded-For` believed instead (`routes_auth.py: resolve_client_ip`).
With mTLS the binding is the certificate CN and the address is irrelevant.

**Health vs readiness.** `/health` answers `{"status": "ok"}` after a Redis
ping. `/ready` answers 200 `{"status": "ready"}` only when Redis pings OK
*and* at least one `users:*` record exists (the directory is seeded); otherwise
503 `{"status": "not_ready", "detail": ...}` (`routes_health.py`).

## Redis key schema

Verified against `control-plane/app/state.py` and `identity.py`.

| Key | Value | Written by | Lifetime |
|---|---|---|---|
| `route:<binding>` | `"host:port"` of the one authorized tunnel | PDP login gate | 3600 s (`AEGISX_ROUTE_TTL`) |
| `sess:<binding>` | hash `{user, role, app, target, jti, client_ip, device}` — the PDP's view of the live session | PDP | same as the route |
| `users:<name>` | hash `{password_hash, role, apps, device}` — the user directory | seeded at startup | none |
| `jwt:deny:<jti>` | `"1"` — revoked token | PDP logout / admin revoke | token's remaining `exp` |
| `login:rl:<user>` | per-user login-attempt counter | login gate | 60 s window |
| `ipl:<client_ip>` | per-source-IP login-attempt counter | login gate | 60 s window |
| `fails:<user>` | consecutive failed logins (drives lockout) | login gate | 300 s |
| `lock:<user>` | `"1"` — account locked | login gate | 300 s |
| `audit:events` | Redis Stream: every allow/deny/login/logout/admin action | both planes | capped at 10,000 entries |
| `pep:allow`, `pep:deny`, `pep:active`, `pep:closed`, `pep:revoked` | enforcement counters | PEP | none |
| `logins:ok`, `logins:denied`, `admin:revocations` | PDP counters | PDP | none |

`<binding>` is `device:<cert CN>` for certificate-bound sessions, otherwise
the source address (`state.binding`).

## The two Lua scripts

Both live in `control-plane/app/state.py`. They exist so concurrent control
planes can never interleave a login against a logout — no distributed locks.

- **`LOGIN_LUA` (login gate):** lockout check + per-user and per-IP rate
  accounting + failure-streak tracking + route provisioning, in one atomic step.
- **`LOGOUT_LUA` (revocation):** denylist the token's `jti` + delete the
  route + delete the session record, in one atomic step — the PEP can never
  see a half-revoked session.

## Honest limitations

- **Demo PKI.** `certs/` is throwaway material from `scripts/gen_certs.sh`;
  `ca.key` sits in the clear and must never leave a test machine. There is no
  certificate enrollment or certificate revocation — only session revocation.
- **Key custody is the trust anchor.** Whoever can read a client's private key
  can act as that identity. The demo keys live unencrypted in `certs/`.
- **`/dashboard/state` is unauthenticated** on purpose, so the explainer page
  works with no setup. It exposes session identities and audit events and must
  sit behind admin auth in any real deployment. (`/admin/*` already requires
  an admin-role token.)
- **Single Redis is a single point of failure.** The PEP fails closed, so a
  state-store outage means a global lockout rather than a breach — but it is
  still a lockout. Production uses Sentinel/Cluster.
- **Revalidation is polling** (default 5 s), so a revoked tunnel can live up
  to one interval after revocation. A Redis pub/sub revocation bus would cut
  that to milliseconds.
- **Localhost demo topology.** Everything collapses onto one IP locally (and,
  in Docker, onto the Docker gateway IP for host-originated clients). mTLS
  device binding is what separates identities sharing an address.
- **JWT secret defaults to a dev value** (`AEGISX_JWT_SECRET` must be
  overridden in any non-local deployment).
- **The Redis user directory replaces a real IdP.** The seam is one function
  (`identity.verify_credentials`) — swap it for an OIDC call and the rest of
  the pipeline is unchanged.
- **L4 only.** The PEP forwards bytes; it does not inspect protocols, so a
  tunnel to `internal-api` could carry any protocol that fits the port.
