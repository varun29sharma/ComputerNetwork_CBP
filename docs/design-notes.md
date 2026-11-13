# AegisX design notes

The long-form academic detail behind the README: certificate identity, the
NIST SP 800-207 mapping, the key design decisions, and the deliberate
simplifications. Moved verbatim out of the README during the November 2026
rework so the README stays short and resume-friendly — no knowledge was
deleted, it just lives here now.

> **Note (Nov 2026 rework):** one item below is now out of date. The
> "client-supplied `client_ip`" demo shortcut described in the security notes
> is fixed: logins are bound to the socket's real peer address, and
> `X-Forwarded-For` is believed only when `AEGISX_TRUST_PROXY=1`
> (`routes_auth.py: resolve_client_ip`). The section is kept verbatim as the
> design record; the current rule is documented in
> [architecture.md](architecture.md).

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

## Mapping to NIST SP 800-207 / CSA SDP

| NIST SP 800-207 role | AegisX implementation |
|---|---|
| Policy Decision Point (PDP) | FastAPI control plane |
| Policy Engine (PE) | `POST /auth/login`: credential check, entitlement resolution, device-posture evaluation, JWT minting |
| Policy Administrator (PA) | Lua-atomic `route:<client_ip>` provisioning / teardown, `/admin/sessions`, `/admin/revoke` |
| Policy Information Point (PIP) | `users:<name>` directory in Redis ([identity.py](../control-plane/app/identity.py)), the seam for an OIDC/LDAP connector |
| Policy Enforcement Point (PEP) | Netty `ZtnaAuthHandler`; **default-deny**, no autonomous trust decisions |
| Continuous verification | PEP re-reads the route every `AEGISX_REVALIDATE_SECONDS` (default 5) and closes tunnels whose session no longer exists |
| Authorization identity (binding) | `device:<cert CN>` when a client certificate is verified, otherwise the source address ([state.py](../control-plane/app/state.py)); the address is never consulted for a certificate-bound session |

CSA SDP behaviors realized: *Authenticate-Before-Connect* (`AUTO_READ=false`
until the Redis route record authorizes the source IP, and no backend connect
before authorization even when mTLS requires reads), *resource cloaking*
(unauthorized connections are closed with no application-layer response), and
*connection-defined segmentation* (one identity → one `host:port`
micro-tunnel with a 3600 s TTL, not a subnet).

## Key design decisions (per the report)

**JWT revocation — denylist, not allowlist.** Only *revoked* jtis occupy
memory (`jwt:deny:<jti>`), and each entry's TTL mirrors the token's remaining
`exp`, so Redis prunes entries by itself the moment the token would die
anyway. Pair with `maxmemory-policy volatile-ttl` in production `redis.conf`.
`/auth/logout` also deletes the PEP's route key in the same Lua script, so
control-plane revocation and data-plane revocation are one atomic step.

**Lua for atomicity.** Two embedded scripts ([state.py](../control-plane/app/state.py)):
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
  [ROADMAP.md](../ROADMAP.md) item 1.2b.
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
