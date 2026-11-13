# INTERVIEW-GUIDE.md — AegisX

How to talk about this project in an interview or viva. Everything here is
true of the code in this repo — if you are asked for proof, the file or the
command is named.

## 30-second pitch

> "AegisX is a zero-trust network access gateway I built to replace
> implicit-trust VPNs. You authenticate to a Python control plane first; only
> then does it write a one-identity, one-app tunnel into Redis. The Java
> gateway then lets that one connection through and silently drops everyone
> else — the protected app is invisible to unauthenticated clients. Sessions
> are re-checked every five seconds, so revoking access kills open tunnels
> too. 64 tests, Docker Compose demo, and a dashboard that shows the live
> Redis state."

## 2-minute deep dive

> "It follows the NIST SP 800-207 split. The control plane is the Policy
> Decision Point: a FastAPI app that verifies credentials, checks the app
> entitlement, the registered device certificate and the device posture, then
> writes a single Redis key, `route:<binding>`, with a one-hour TTL. The
> data plane is the Policy Enforcement Point: a Netty proxy in Java. When a
> TCP connection arrives it looks up that key — one async Redis read. If the
> key exists it opens a tunnel to the app; if not, it closes the connection
> with no payload. That is cloaking, from the SDP spec: an attacker cannot
> even tell the app exists.
>
> Two design choices I am proud of. First, the PDP never calls the PEP —
> Redis is the only link, so either plane can restart independently. Second,
> everything that must be atomic is a Lua script: the login gate does the
> lockout check, the rate-limit bump and the route write in one script, so
> two parallel logins cannot both slip past the check. And revocation is
> real: logout denylists the JWT's `jti` and deletes the route, and the PEP
> re-validates every open tunnel every five seconds, so an already-open
> tunnel dies within seconds of a revoke. The demo script proves all five
> claims on a live stack."

## Likely questions — short, confident answers

### 1. What is ZTNA, and how is it different from a VPN?

A VPN authenticates once and then trusts everything on the network — it is a
moat. ZTNA authenticates *per application, per session*, and never trusts the
network: no login, no route, no connection. Here the proof is concrete: before
login, the PEP closes your TCP connection with no payload at all. A VPN would
at least show you the network.

### 2. Walk me through a login, packet by packet.

`POST /auth/login` → the PDP verifies the password (PBKDF2), checks the
entitlement, the device registration and the posture → the Lua login gate
atomically checks lockout/rate limits and writes `route:127.0.0.1 =
127.0.0.1:8080` with a 3600 s TTL → the PDP mints a JWT and stores the session
hash → the client opens a TCP connection to the PEP on :9000 → the PEP reads
the route key, connects to :8080, and relays bytes both ways.

### 3. Why is Redis between the two planes instead of the PDP calling the PEP?

Decoupling. The PDP can restart, scale or be replaced without the PEP caring,
and the PEP only needs one fast read per connection. It also makes the state
inspectable — the dashboard literally shows the route keys — and it gives us
TTL-based expiry for free: a route that is never revoked still dies after an
hour.

### 4. What is mTLS, and why does this project use it?

In normal TLS only the server proves who it is. In mutual TLS the client
presents a certificate too, so the gateway knows *which device* is connecting
before any application data flows. Here the certificate's Common Name
(`device:alice`) becomes the session binding, so a route is tied to a device,
not just an IP address — another process on the same host cannot ride it.
(`ZtnaProxyServer.buildServerSslContext`, `ZtnaAuthHandler.clientCertCommonName`)

### 5. Certificate CN vs IP identity — why have both?

IP addresses are weak identity: they change (DHCP, NAT) and they are shared
by every process on a host. A certificate CN is a cryptographic identity tied
to a private key. The binding rule is: device CN if the login asserted one,
otherwise the source IP. The login also enforces that you can only assert the
device registered to *your* user, so one user cannot claim another's
certificate. (`identity.device_matches`)

### 6. How does JWT revocation work? JWTs are supposed to be stateless.

They are, which is exactly why revocation needs state. Every token carries a
unique `jti`. On logout or admin revoke, the `jti` goes on a Redis denylist
with the token's remaining TTL, and `current_identity` checks the denylist on
every request. So a revoked token fails within one request, and the denylist
entry expires on its own when the token would have expired anyway — no cleanup
job needed.

### 7. Denylist vs allowlist — why a denylist here?

An allowlist would mean storing every valid token and checking membership on
every request — that is a database lookup that grows with users. A denylist
only stores the *revoked* tokens, which are few, and each entry self-expires.
The tradeoff is that a stolen token is valid until revoked — which is why the
token lifetime is short (1 hour) and the PEP re-validates tunnels every 5
seconds independently of the token.

### 8. Why Lua scripts? Why not just do the checks in Python?

Because "check, then write" in two Redis calls has a race: two parallel
requests can both pass the check before either writes. A Lua script runs
atomically inside Redis — nothing else interleaves. `LOGIN_LUA` does the
lockout check, the rate-limit increments and the route write in one step;
`LOGOUT_LUA` denylists the `jti` and deletes the route and session in one
step, so a revoke can never leave half the state behind.

### 9. Netty EventLoop vs blocking Jedis — why does the client choice matter?

A Netty EventLoop is a single thread handling many connections. If a handler
blocks — say, a Jedis call waiting 10 ms for Redis — *every* connection on
that loop stalls for 10 ms. Lettuce is async and built on Netty itself: the
route lookup returns a future, the EventLoop keeps serving other connections,
and the tunnel opens when the future completes. That is why the PEP can hold
many concurrent connections with a handful of threads. (`ZtnaAuthHandler`
uses `RedisAsyncCommands`; the load test in `scripts/loadtest_pep.py` measures
accept-to-close latency under concurrency.)

### 10. What is cloaking, and how do you prove it?

Cloaking (from the SDP "dark network" idea) means an unauthorized client gets
nothing: the connection is accepted and then closed before any payload is
read — no banner, no error, no RST with a message. You cannot distinguish the
protected app from a dead port. The proof is the probe: `POST /demo/probe`
opens a real TCP socket and reports "connection closed before any payload was
read (cloaked)". `scripts/demo_e2e.sh` asserts this on a live stack.

### 11. What is continuous revalidation, and why 5 seconds?

"Authenticate once and trust forever" is the VPN failure mode. Here every open
tunnel is re-checked against Redis every 5 seconds (default,
`AEGISX_REVALIDATE_SECONDS`): if the route key is gone or points somewhere
else, the tunnel is torn down mid-flow. Five seconds is the tradeoff — short
enough that a revoke lands quickly, long enough that the Redis load is one
tiny GET per tunnel per 5 s. (`ZtnaAuthHandler.scheduleRevalidation`)

### 12. What does "fail closed" mean here? Give examples.

When something is uncertain, deny. Examples: posture strict mode fails on a
*missing* claim, not just a bad one; a login with no determinable client IP is
a 400, not a guess; if the route key is absent the PEP denies — there is no
"allow on error" path; if Redis is unreachable the PEP cannot authorize, so
nothing gets through. The `/ready` endpoint is the same idea for deployment:
no seeded users means not ready, so no traffic is routed to the instance.

### 13. How do you stop someone spoofing `client_ip` in the login JSON?

By default the JSON value is ignored entirely — the session is bound to the
socket's real peer address. The payload value is only honoured behind a
trusted reverse proxy (`AEGISX_TRUST_PROXY=1`), where the proxy overwrites
`X-Forwarded-For` itself, and then the header's first entry wins. There is a
test that posts a spoofed IP with the proxy off and asserts the route is bound
to the socket IP instead. (`resolve_client_ip`, `tests/test_trust_proxy.py`)

### 14. How does the rate limiting / lockout work?

Per-user and per-IP counters in Redis, bumped inside the atomic login gate:
too many attempts in the window returns 429 with a `Retry-After` header, and
repeated failures lock the account (423) for a fixed period. Because the
counters live in the Lua script, the check and the increment cannot race, and
because lockout state is in Redis (not process memory), it survives PDP
restarts.

### 15. What are the honest limitations?

Four, and I would say them unprompted — interviewers trust that. One, the
user directory is a demo stand-in for an OIDC/LDAP IdP, with demo passwords in
`identity.py`. Two, `/dashboard/state` is unauthenticated on purpose for the
demo; production gates it behind admin auth. Three, it is a single Redis with
no HA — if Redis dies, no new tunnels open (fail closed, but still down).
Four, the tunnel destination is hardcoded per app in `APP_TARGETS`; making it
environment-driven is the next change (the compose file documents this).

## If they ask you to demo it (60 seconds)

1. `docker compose up`, open http://127.0.0.1:8000/
2. Click **Probe** before logging in → CLOAKED.
3. Log in as `alice` / `alice-dev-pw` → route appears in the Redis inspector.
4. Click **Probe** again → allowed, and the target answers.
5. Click **Watch a decision happen** → allow, revoke, deny, on a real socket.
6. Revoke alice's session from the admin console → the tunnel dies within 5 s.

Full script: `docs/demo-script.md`.
