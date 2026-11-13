# FUNCTION-GUIDE.md — AegisX, every file and function in plain English

Read this before an interview. Java (the PEP, the data plane) first — that is
where interviewers dig first — then Python (the PDP, the control plane), then
the JavaScript dashboard. One line per function: what it does, and why it
exists.

## The system in one paragraph

A client logs in to the **PDP** (Python/FastAPI, port 8000). The PDP checks the
password, the app entitlement, the device certificate and the device posture,
then writes one Redis key, `route:<binding> = host:port`. The client then
opens a TCP connection to the **PEP** (Java/Netty, port 9000). The PEP reads
that Redis key: if it exists, it opens a tunnel to the protected app; if not,
it silently closes the connection (cloaking — the app looks like it does not
exist). Every 5 seconds the PEP re-checks the key, so revoking a session kills
even an already-open tunnel. Redis is the only link between the two planes;
the PDP never calls the PEP.

---

## Part 1 — Java data plane (PEP), `data-plane/src/main/java/io/aegisx/ztna/`

### `ZtnaProxyServer.java` — starts the gateway

| Function | What it does, and why |
|---|---|
| `main(args)` | Reads env (PEP port, Redis URL, revalidate seconds), connects to Redis with Lettuce, builds the Netty server bootstrap, binds port 9000. The entry point — everything else hangs off the pipeline it builds. With `AEGISX_PEP_REQUIRE_READY=1` it first runs the readiness gate (below) and never binds if the PDP is not ready. |
| `initChannel(SocketChannel)` | Wires one accepted connection's pipeline: optional TLS handler, then `ZtnaAuthHandler`. Runs once per TCP connection, which is how each connection gets its own auth state. |
| `requireControlPlaneReady(pdpUrl)` | Polls the PDP's `/ready` endpoint up to 10 times with 1–5 s backoff; if it never answers 200, logs an error and exits(1) without binding. A PEP that cannot reach its PDP must not accept connections — it could only cloak everyone. |
| `controlPlaneReady(readyUrl)` | One readiness probe: true only on HTTP 200, false on any failure (2 s connect/read timeouts). Returns a boolean instead of throwing, so the retry loop stays simple. |
| `sleepSeconds(seconds)` | Sleeps between readiness probes; restores the interrupt flag if interrupted, so the wait cannot swallow a shutdown signal. |
| `mtlsEnabled()` | Returns true only when `AEGISX_MTLS=1`, so plain-TCP demos and mTLS demos share one binary. |
| `buildServerSslContext()` | Loads the PEP's cert/key and the CA, requires a client certificate. Exists so the gateway can verify *who* is connecting at the TLS layer, before any app bytes flow. |
| `required(name)` | Reads a mandatory env var or fails fast with a clear error — better than starting half-configured and failing mysteriously mid-demo. |
| `env(name, fallback)` | Reads an env var with a default, so every setting is overridable without recompiling. |

### `ZtnaAuthHandler.java` — the gate (the most important file in the project)

One instance per connection. Its five numbered sections are the story to tell
in an interview: **auth check → Redis lookup → tunnel open → revalidation →
close** — with a **2b revocation check** between lookup and tunnel-open for
certificate-bound sessions: a route is not enough if the certificate itself
was revoked.

| Function | What it does, and why |
|---|---|
| `ZtnaAuthHandler(redis, revalidateSeconds)` | Constructor: keeps the async Redis commands and the revalidation interval. The handler needs Redis on every connection, so it is injected once, not looked up per packet. |
| `channelActive(ctx)` — §1 auth check | Fires when a TCP connection opens. With mTLS it waits for the TLS handshake, then reads the client certificate's Common Name as the device identity; without mTLS it uses the remote IP. Runs before any payload is read, so an unauthorized client never gets to send a request. |
| `beginAuthorization(ctx, device)` | Decides the binding (device CN if present, else remote IP) and kicks off the Redis lookup. Separates "who is this" from "are they allowed", so each half is easy to explain. |
| `authorize(ctx, remoteIp, routeKey, rawTarget)` — §2 Redis lookup | The `route:<binding>` GET returned: if a target exists, open the tunnel; if not, deny. This is the allow/deny decision, and it is one Redis read — fast and simple. For certificate-bound sessions it first hands off to `checkCertNotRevoked` (below) instead of opening the tunnel directly. |
| `checkCertNotRevoked(ctx, remoteIp, device, routeKey, target)` — §2b revocation check | Async check of `cert:deny:<CN>`: key present means deny (cloaked, audited as `cert-revoked:<CN>`); a Redis error fails closed, exactly like the route lookup. Async for the same reason as the route lookup — a blocking Redis call would stall the EventLoop. Live-unverified (Java TCP is blocked in the build VM). |
| `initChannel(ch)` (inner, backend side) | Wires the *backend* connection's pipeline (the PEP → app leg) with the relay handlers. A tunnel is two connections, so it needs two pipelines. |
| `scheduleRevalidation(client, remoteIp, routeKey, expectedTarget)` — §4 | Starts a timer on the connection's EventLoop that re-reads the route key every N seconds (default 5). This is continuous verification: revoking a session kills tunnels that are *already open*, not just future ones. |
| `revokeOpenTunnel(client, remoteIp, reason)` | Called by the revalidation timer when the route is gone or changed: logs the revoke and closes the tunnel. The enforcement arm of continuous verification. |
| `closeTunnel(client, remoteIp, target)` — §5 close | Stops the revalidation timer, decrements the active-tunnel counter, closes both legs. Without the timer stop, a closed tunnel would leak a scheduled task forever. |
| `deny(ctx, remoteIp, reason)` | Cloaks: closes the connection with no payload and bumps the deny counter. No error page, no RST with a message — the protected app is indistinguishable from a dead port. |
| `channelRead(ctx, msg)` | Handles bytes arriving before authorization finished (mTLS mode only): parks them in a pending queue instead of dropping them, so the TLS handshake bytes are not lost. |
| `replayPending(client, backend)` | On allow, writes the parked bytes into the new tunnel — the client's first request is not lost because auth took a moment. |
| `releasePending(client)` | On deny, frees the parked buffers. Netty buffers are reference-counted; forgetting this leaks memory on every denied connection. |
| `exceptionCaught(ctx, cause)` | Logs the error and closes the channel. A gateway must never let one bad connection kill the EventLoop. |
| `incr(key)` / `decr(key)` | Fire-and-forget Redis counter bumps (`pep:allow`, `pep:deny`, `pep:active`) so the dashboard can show enforcement numbers. Async on purpose — counting must never block the data path. |
| `audit(event, remoteIp, target, device, reason)` | Writes one audit event to the Redis Stream, so the PEP's decisions appear in the same trail as the PDP's. |
| `clientCertCommonName(ssl)` | Pulls the Common Name out of the verified peer certificate — the device identity (`device:alice`) that keys certificate-bound routes. |

### `RouteTarget.java` — one tiny value object

| Function | What it does, and why |
|---|---|
| `parse(value)` | Turns a route value like `127.0.0.1:8080` into host + port, or fails clearly on garbage. Routes are stored as plain strings in Redis, so parsing lives in exactly one place. |
| `toString()` | Prints `host:port` again, for logs and the dashboard. |

### `FrontendToBackendHandler.java` — client → app relay

| Function | What it does, and why |
|---|---|
| `channelRead(ctx, msg)` | Forwards each chunk of client bytes to the backend channel. One relay per direction keeps the code trivially explainable. |
| `channelInactive(ctx)` | When the client goes away, closes the backend leg too — a tunnel with one dead leg must not linger. |
| `exceptionCaught(ctx, cause)` | Logs and closes; same "one bad connection never kills the gateway" rule. |

### `BackendToFrontendHandler.java` — app → client relay

Same three functions, mirrored: `channelRead` forwards app bytes to the
client, `channelInactive` closes the client leg when the app goes away,
`exceptionCaught` logs and closes.

---

## Part 2 — Python control plane (PDP), `control-plane/app/`

### `main.py` (~70 lines) — wiring only

| Function | What it does, and why |
|---|---|
| `lifespan(app)` | On startup: connects to Redis and seeds the demo users; on shutdown: closes Redis. Seeding at startup is what makes `/ready` meaningful and the demo work with zero setup. |
| `dashboard_page()` | Serves `index.html` at `/` and `/dashboard`. The static mount next to it serves the CSS/JS. |

The five routers are included here: `routes_auth`, `routes_admin`,
`routes_demo`, `routes_health`, `routes_policy`. (If an interviewer asks "where is login?" —
`routes_auth.py`, not `main.py`.)

### `deps.py` — auth dependencies

| Function | What it does, and why |
|---|---|
| `current_identity(request, authorization)` | Decodes the Bearer JWT and rejects it if the `jti` is on the Redis denylist. Runs on *every* protected request, so revocation takes effect immediately instead of waiting for expiry. |
| `require_admin(claims)` | Builds on `current_identity` and additionally requires `role == "admin"`. Keeps the admin check in one place instead of repeating it in four endpoints. |

### `routes_auth.py` — login / logout / verify / service login

| Function | What it does, and why |
|---|---|
| `resolve_client_ip(request, body_client_ip)` | Picks the address the session is bound to. Default: the socket's real peer address — the JSON body value is attacker-controlled, so believing it would let anyone ride another host's route. Only with `AEGISX_TRUST_PROXY=1` does it trust `X-Forwarded-For` (first entry), falling back to the body value. |
| `_deny_if_lockdown(redis, subject, client_ip)` | Raises 403 (and audits it) when emergency lockdown is on. Shared by both login paths — a password login and a service-key exchange are both logins, so lockdown stops both. |
| `login(body, request)` | The Policy Engine + Administrator: lockdown check first, then verify credentials → check device registration → check the certificate is not revoked → check entitlement → check posture → check the time window → atomic `login_gate` (lockout + rate limits + route write, with the app's per-app TTL) → mint JWT → store session → audit. The order matters: a denied login must never leave a usable tunnel behind. |
| `service_login(body, request)` | Exchanges a service account's API key for a JWT (`role=service`) for exactly the one app the account was created for. Compares the key by hash (constant-time), then runs the same lockdown check, time-window check, login gate and session write as a password login — a machine identity is still a login. |
| `logout(request, claims)` | Denylists the token's `jti` and atomically deletes route + session. Finds the route by the *binding in the token*, so a certificate-bound session is torn down even from a different address. |
| `verify(claims)` | Returns 200 only if the token is valid *and* not denylisted — the continuous-verification probe the UI and tests use. |

### `routes_admin.py` — the SOC console

| Function | What it does, and why |
|---|---|
| `_revoke_sessions(redis, **match)` | Revokes every live session whose record matches the given fields (no fields = all of them — the lockdown path). Each session goes through the same revoke path as `/admin/revoke`, so open tunnels die at the next PEP revalidation. One helper, so device-revoke, user-disable and lockdown cannot drift apart. |
| `_as_422(message)` | Builds a 422 error for a bad caller-supplied value — a caller error, not a server error, with a message that says what is wrong. |
| `admin_sessions(request, claims)` | Lists every live tunnel with its identity — the "who is connected right now" view. |
| `admin_revoke(body, request, claims)` | Force-revokes a session by device or IP: looks up the session, denylists its `jti`, deletes route + session. The admin never needs the victim's token. |
| `admin_audit(request, limit, claims)` | Returns the recent audit trail (Redis Stream) — every allow/deny decision in one place. |
| `admin_audit_export(request, format, limit, claims)` | Downloads the audit trail as JSON (default) or CSV (up to 500 events), and audits the export itself. The stream is capped at 10,000 entries, so an offline copy is the only archive. |
| `admin_apps(claims)` | Returns the protected apps and their posture rules — from the LIVE policy, so an admin PUT shows up here immediately, not just at the next login. |
| `register_device(body, request, claims)` | Registers a device (certificate CN) to an existing user, so that user may assert this device — and only this device. Validates the CN with the same pattern the demo routes use, so it can never smuggle a path or key separator into Redis or the certs directory. |
| `revoke_device(body, request, claims)` | Revokes a device certificate: writes `cert:deny:<CN>` (24 h TTL) AND revokes the CN's live sessions. The deny key alone only blocks *new* tunnels, so without the session revoke an open tunnel would survive until its TTL. |
| `create_user(body, request, claims)` | Creates a directory user (PBKDF2-hashed password, role, entitlements, optional device). Entitlements must name apps the live policy knows, or the user could never log in to them. Returns 409 on a duplicate username. |
| `disable_user(name, request, claims)` | Disables an account AND revokes its live sessions. Afterwards the login fails with the same 401 as a wrong password, so a disabled account is indistinguishable from a wrong password to anyone probing. |
| `enable_user(name, request, claims)` | Re-enables an account by deleting the `disabled` flag (not setting it to "0"), so a fresh account and a re-enabled one look identical in Redis. |
| `list_lockouts(request, claims)` | Lists locked users (`lock:*`) and rate-limited IPs (`ipl:*`) with remaining seconds — the "who is locked out right now" view. |
| `unlock(body, request, claims)` | Clears a lockout: the failure streak and the lock for a user, and/or the rate-limit window for an IP. At least one of the two must be given. |
| `set_lockdown(body, request, claims)` | Switches emergency lockdown on or off. Turning it ON also revokes every live session, so open tunnels die within one PEP revalidation interval instead of lingering until their TTL. |
| `get_lockdown(request, claims)` | Reports whether emergency lockdown is on right now. |
| `create_service_account(body, request, claims)` | Creates a service account for one app. The API key is shown ONCE, in this response — only its SHA-256 hash is stored, so a leaked database does not leak usable keys. |

### `routes_policy.py` — policy-as-data CRUD (new in batch 2)

| Function | What it does, and why |
|---|---|
| `_as_422(message)` | Same idea as the admin one: a bad rule is the caller's fault (422), with a message that says what is wrong. |
| `list_policy(request, claims)` | Returns the whole live policy, keyed by app name — the single source of truth the dashboard editor reads. |
| `upsert_policy(app, body, request, claims)` | Creates or updates one app's policy record. Fields not sent keep their current value; `target` is required for a new app. Validates the *merged* record (target, hours, TTL), so a partial update can never leave a broken record behind. Then writes to Redis, invalidates the policy cache (hot reload) and audits the change. |
| `delete_policy(app, request, claims)` | Removes an app from the policy; a later login for it is denied as unknown. The seed never brings it back (see `policy:seeded`). |

### `routes_demo.py` — probe, attempt, metrics, dashboard feed

| Function | What it does, and why |
|---|---|
| `_app_row(name, target, posture)` | One app's public description (name, target, posture rules) — shared by `/apps`, `/admin/apps` and `/dashboard/state` so they cannot drift apart. |
| `metrics(request)` | Aggregates the PDP + PEP counters from Redis into one JSON object for the dashboard. |
| `apps()` | Public list of protected apps, so the UI can offer them in the login form without needing a login first. |
| `_cert_paths(name)` | Resolves a demo certificate name to files inside `certs/`, refusing anything that escapes the directory — a demo endpoint must not become an arbitrary file reader. |
| `_cert_common_name(path)` | Reads the CN out of a PEM certificate with the stdlib only — no extra dependency for a demo helper. |
| `_available_certs()` | Lists the demo client certificates (excluding `ca` and `pep`) for the UI's cert selector. |
| `demo_probe(body)` | POST `/demo/probe`: opens a **real TCP connection** to the PEP (optionally with a client cert) and reports what the gate decided. The demo's proof is a live socket, not a prediction. |
| `_run_probe(addr, cert_name)` | The shared socket logic behind `/demo/probe` and `/demo/attempt`, so both exercise one identical enforcement path. |
| `_delivered_port(payload)` | Figures out which app instance answered, from the hold banner or the JSON `"port"` field — proves *which* app the tunnel reached. |
| `_app_for_port(port, policy)` | Maps a port back to an app name via the live policy. |
| `demo_attempt(body, request, claims)` | Traces one "access that application" attempt gate by gate (identity → entitlement → authorization record → real TCP through the PEP) and reports the final decision, the reason, and which app physically answered. |
| `_pep_reachable()` | Plain TCP connect to the PEP with a 0.3 s timeout; returns (reachable, latency_ms). No payload is sent — the PEP cloaks, so bytes would prove nothing — and any failure means unreachable, never an error, so a dead PEP can never hang the dashboard feed. |
| `_is_admin_request(request)` | True only when the request carries a valid, non-revoked ADMIN token. Reuses `current_identity`, so the dashboard gate can never drift from the real auth path; a failure means "redacted view", not an error. |
| `dashboard_state(request)` | The demo-only live feed: routes, denylist, rate limits, sessions, lockouts, audit, metrics, apps, users, certs, PEP reachability, and the lockdown flag. One endpoint, so the UI polls once instead of ten times. With `AEGISX_DASHBOARD_AUTH=1` and no admin token it returns only the public fields (metrics, apps, PEP reachability, certs) — a 200 redacted view, never an error — and skips the Redis scans for the withheld fields entirely. |

### `routes_health.py` — liveness, readiness and Prometheus metrics

| Function | What it does, and why |
|---|---|
| `metrics_prometheus(request)` | `/metrics/prometheus`: the same counters `/metrics` returns, in Prometheus text format (7 counters, 2 gauges, plus an `aegisx_uptime_seconds` gauge measured from import time). Same source of truth (`state.metrics`), so the two endpoints can never disagree. |
| `health(request)` | `/health`: 200 if Redis answers a ping. Liveness — "is the process up". |
| `ready(request)` | `/ready`: 200 only if Redis pings OK **and** at least one `users:<name>` record exists. Without seeded users every login would 401, so the instance must not receive traffic yet. |

### `config.py` — every knob in one place

Plain constants read from env with defaults: `REDIS_URL`, `JWT_SECRET`,
`ACCESS_TOKEN_TTL_SECONDS` (3600), `ROUTE_TTL_SECONDS` (3600),
`POSTURE_STRICT`, `PEP_PROBE_ADDR` (`127.0.0.1:9000`), `CERTS_DIR`,
`POLICY_CACHE_SECONDS` (5 — the policy cache TTL; admin writes invalidate
it immediately, so this is only a backstop), `DASHBOARD_AUTH` (off —
`AEGISX_DASHBOARD_AUTH=1` redacts `/dashboard/state` without an admin
token). One file so a reviewer can see every setting without hunting.

### `identity.py` — the demo directory (stand-in for an IdP) + policy-as-data

| Function | What it does, and why |
|---|---|
| `default_record(app)` | Builds the seed policy record for one app from the `APP_TARGETS` / `POSTURE_RULES` constants — the values a fresh install starts from. |
| `_seed_policy()` | The whole seed policy, for callers with no Redis policy loaded (the demo routes). |
| `seed_policy(redis)` | Idempotently creates the `policy:apps` hash from the seed defaults (`HSETNX` per app, so an admin edit made before a restart is never overwritten) and sets the `policy:seeded` marker. |
| `invalidate_policy_cache()` | Drops the cached policy; the next `get_policy()` re-reads Redis. Called by every admin policy write — this is what makes a rule change live on the next login (hot reload). |
| `get_policy(redis)` | Returns the live policy (`{app: record}`), from a 5 s in-memory cache when fresh, else from Redis (seeding first if the hash does not exist). Every login reads policy through this one function, so every check in a login judges the same rules. |
| `policy_now()` | Local server time, behind one function so tests can monkeypatch the clock instead of depending on the real wall time. |
| `parse_allowed_hours(value)` | Parses `"HH:MM-HH:MM"` into (start, end); `""` means always allowed. Rejects overnight/inverted ranges — a window must fit inside one day, so `"22:00-06:00"` is an error, not a surprise. |
| `time_window_denial(record)` | `None` if the app is usable right now, else a denial message that names the window — so the user knows *when* to come back. Fails closed on a misconfigured record. |
| `validate_target(target)` | `'host:port'` with a numeric port 1–65535; raises `ValueError` otherwise. Runs on the merged record at write time, so a partial update can never leave a broken record behind. |
| `validate_session_ttl(ttl)` | Per-app session TTL must fit 60–86400 s; shorter than a minute is useless for a tunnel, longer than a day defeats the point of an ephemeral micro-tunnel. |
| `user_key(username)` | Builds the `users:<name>` Redis key. Key-building lives in one place so a typo cannot create a second, invisible namespace. |
| `service_key(name)` | Builds the `svc:<name>` Redis key for a service account — same one-place rule as `user_key`. |
| `hash_api_key(api_key)` | SHA-256 fingerprint of an API key, for storage and comparison. The key itself is never stored, so it can never be read back. |
| `hash_password(password, salt)` | PBKDF2-HMAC-SHA256 with a random salt — passwords are never stored or compared in plaintext, even in a demo. |
| `seed_users(redis)` | Writes the three demo users (alice, bob, admin) at startup if missing. Idempotent, so restarts are safe. |
| `get_user(redis, username)` | Reads one user record from Redis. A record without a password hash is treated as "no such user" rather than trusted. Includes the `disabled` flag. |
| `verify_credentials(redis, username, password)` | Constant-time password check; returns the user or `None`. Runs a dummy hash for unknown users so the timing does not reveal whether an account exists. A disabled account fails exactly like a wrong password (same 401, same timing). |
| `_hash_password_dummy(password)` | The dummy hash above — burns the same time as a real check. |
| `choose_app(user, requested, policy)` | Picks the app: the requested one if the user is entitled, else the user's first entitled app, else raises `PolicyError`. Also rejects an app removed from the policy or marked `enabled: false`. One function owns the entitlement decision. |
| `registered_device(user)` | Returns the certificate identity registered to a user (e.g. `device:alice`). |
| `device_matches(user, device)` | True only if the asserted device is the one registered to that user — stops one user riding another's certificate. |
| `directory_summary()` | Public, password-free view of the directory for the dashboard. |
| `evaluate_posture(app, posture, strict, policy)` | Returns a list of failed posture rules for an app (e.g. firewall off). Empty list = pass. Rules come from the live policy record when one is passed, else the seed constants. Strict mode also fails on *missing* claims — fail closed. |

### `security.py` — JWT minting and checking

| Function | What it does, and why |
|---|---|
| `mint_token(username, role, client_ip, device, binding)` | Signs a JWT (HS256) with `sub`, `role`, `client_ip`, `device`, `binding`, a unique `jti`, and a 1-hour expiry. The `jti` is what makes revocation possible — without it a token is un-revocable until expiry. |
| `decode_token(token)` | Verifies the signature and expiry and returns the claims. Raises on anything invalid, so callers never have to check twice. |

### `state.py` — all Redis access (the only module that talks to Redis)

Key builders (`binding`, `split_binding`, `route_key`, `session_key`,
`denylist_key`, `rate_limit_key`, `ip_rate_key`, `fails_key`, `lock_key`,
`cert_deny_key`):
each builds one key name. Centralising them means a rename is one edit and a
typo is impossible to hide.

| Function | What it does, and why |
|---|---|
| `connect()` | Opens the async Redis client from `REDIS_URL`. One connection, shared by the app. |
| `is_lockdown(redis)` / `set_lockdown(redis, on)` | Reads / writes the `admin:lockdown` flag. The key exists ("1") while lockdown is on and is deleted when switched off, so "absent" always means "normal". |
| `revoke_cert(redis, device)` | Writes `cert:deny:<CN>` with a 24 h TTL — the PEP checks this key at tunnel-open time. |
| `is_cert_revoked(redis, device)` | True if the CN has a deny entry — the check the login path runs before provisioning a route. |
| `audit(redis, event, **fields)` | Appends one event to the `audit:events` Redis Stream. A stream (not a list) keeps events ordered with timestamps. |
| `recent_audit(redis, count)` | Reads the newest audit events, newest first, for the dashboard and `/admin/audit`. |
| `set_session(redis, binding, fields, ttl)` | Stores the session hash (`sess:<binding>`) with the same TTL as the route, so the two expire together and can never disagree. |
| `list_sessions(redis)` | Scans `route:*` and returns every live session for the admin console. (Keyed on routes, not sessions — a route is what makes a session live.) |
| `login_gate(redis, username, client_ip, target, binding, ttl)` | Runs `LOGIN_LUA` — one atomic script that checks the lockout, bumps the per-user and per-IP rate counters, and writes the route. Atomic because "check then write" in two steps has a race: two parallel logins could both pass the check. `ttl` is the app's per-app session TTL when the login is for an app, else the global default. |
| `revoke(redis, jti, binding, remaining_ttl)` | Runs `LOGOUT_LUA` — one atomic script that denylists the `jti` and deletes route + session. Atomic so a revoke can never leave half the state behind. |
| `revoke_binding(redis, binding)` | Revokes one live session by its binding — looks the session record up itself, so callers that only know a device or a username never need the victim's token. A route with no session record still has its keys deleted. Returns whether anything was actually revoked. |
| `is_denied(redis, jti)` | True if the `jti` is on the denylist — the check `current_identity` runs on every request. |
| `incr_counter(redis, name)` | Bumps a counter (`logins:ok`, `logins:denied`, `admin:revocations`) for `/metrics`. |
| `metrics(redis)` | Reads all counters (PDP + PEP) into one dict — 7 counters, 2 gauges, plus a live count of `route:*` keys. |

The two Lua scripts (`LOGIN_LUA`, `LOGOUT_LUA`) exist for one reason: Redis
runs a Lua script atomically, so a check-and-write that must not interleave
with another request is safe without locks.

### `schemas.py` — request/response shapes

Pydantic models (`LoginRequest`, `LoginResponse`, `ProbeRequest`,
`ProbeResponse`, `AttemptRequest`, `AttemptResponse`, `AdminRevokeRequest`,
`RevocationResponse`, `VerifyResponse`, `AttemptStage`, plus the batch-2
models: `PolicyRecord`, `PolicyUpdate`, `PolicyListResponse`,
`DeviceRegisterRequest`, `DeviceRevokeRequest`, `CreateUserRequest`,
`UserResponse`, `UnlockRequest`, `LockdownRequest`,
`ServiceAccountRequest`, `ServiceAuthRequest`). They validate every
request body and document the API — FastAPI turns them into the `/docs` page
for free.

---

## Part 3 — Dashboard, `control-plane/app/static/`

### `index.html` — structure only

Sections in order: lockdown banner (top of the page, shown when
`/dashboard/state` reports lockdown), header (title + status pill), login
card, gateway probe card, attempt visualization (`flowviz` SVG + trace),
enforcement counters, live sessions, Redis inspector, audit trail, admin
console (sessions + policy editor + lockout management + lockdown toggle).
Endpoint paths are shown as small mono labels under each panel heading, so
the page itself teaches the API.

### `style.css` — monochrome theme

Black `#000`/`#0A0A0A` surfaces, `#121212` cards, `#262626` hairline borders,
white as the only accent, 999px pill buttons, 20px card radius, uppercase
tracked labels. No gradients, no colour badges — status is words
(ALLOW / DENY / CLOAKED), not colours.

### `app.js` — one small function per job

| Function | What it does, and why |
|---|---|
| `wait(ms)` | Promise-based sleep, so the story animation can pause between steps without nested callbacks. |
| `esc(value)` | HTML-escapes a string before inserting it — the dashboard renders server data, so escaping stops one bad audit entry from breaking the page. |
| `toast(msg, kind)` | Shows a short status message at the top of the page. |
| `log(msg, cls)` / `flowLog(msg, cls)` | Append a line to the event log / the attempt trace, so every action leaves a visible trail. |
| `decodeJwt(t)` | Decodes the payload of the JWT (no verification — display only) so the UI can show who is logged in. |
| `eventClass(ev)` | Maps an audit event name to a CSS class for the trail. |
| `refreshState()` | Polls `/dashboard/state` and re-renders everything. One poll, one render pass. Sends the admin token when one exists (it unlocks the sensitive fields when the dashboard-auth flag is on) and defaults the withheld lists to empty when the feed comes back redacted, instead of crashing on them. Also drives the lockdown banner from `s.lockdown`. |
| `renderMetrics(m)` | Updates the enforcement counters. |
| `fillSelects(s)` | Populates the app and certificate dropdowns from the state feed, so the UI never hardcodes demo data. |
| `renderRedis(s)` | Renders the Redis inspector (routes, denylist, rate limits, lockouts). |
| `renderSessions(sessions)` | Renders the live session table with per-row revoke buttons. |
| `renderAudit(audit)` | Renders the audit trail, newest first. |
| `setGateway(open, route)` | Updates the gateway status pill (open tunnel vs cloaked). |
| `renderJwt(tok)` | Shows the decoded token claims in the JWT panel. |
| `login()` | POSTs `/auth/login` with the form values, stores the token, enables the attempt/probe panels. |
| `logout()` | POSTs `/auth/logout`, clears the token, resets the UI. |
| `clearSessionUI()` | The UI half of logout, shared so login/logout cannot leave the page half-enabled. |
| `probeGateway()` | POSTs `/demo/probe` with the selected cert and renders allowed / cloaked / unreachable. |
| `adminLogin()` | Logs in as admin (no app) to unlock the admin console. |
| `adminRefresh()` | Reloads `/admin/sessions` and `/admin/audit` for the console. |
| `revokeSession(device, ip)` | POSTs `/admin/revoke` for one row and refreshes — the one-click SOC response. |
| `loadPolicy()` | Fetches `GET /admin/policy` with the admin token and stores the live policy for the editor. |
| `renderPolicy()` | Renders one editable card per app (target, posture, allowed hours, session TTL, enabled) with save/delete buttons. |
| `savePolicy(card)` | PUTs one app's edited record to `/admin/policy/{app}` and reloads the list — the hot-reload path from the UI. |
| `deletePolicy(card)` | DELETEs one app from the policy (with a confirm) and reloads the list. |
| `loadLockouts()` | Fetches `GET /admin/lockouts` and renders the locked users / rate-limited IPs with remaining seconds and an unlock button per row. |
| `unlockEntry(username, ip)` | POSTs `/admin/unlock` for one row and reloads the lockout list. |
| `setLockdownUI(on)` | One place owns the lockdown display: the banner, the toggle label and the note text. Called both by the state poll and by the toggle, so the two can never disagree. |
| `toggleLockdown()` | POSTs `/admin/lockdown` to flip the switch (with a confirm when turning it on — it revokes every live session) and updates the UI from the response. |
| `fzNode / fzSeg / fzStop / resetFlow / setFlowButtons` | Small helpers that highlight one node/edge of the flow diagram or reset it — each does one visual thing, so the animation code reads like a script. |
| `fzMove(pathId, tone, ms)` | Animates the dot along one diagram edge. |
| `renderVerdict(a)` | Renders the attempt's final ALLOW/DENY verdict and reason. |
| `runTrace(a)` | Plays the gate-by-gate trace: highlights each diagram node in order as its stage result arrives. |
| `pickSurpriseApp()` / `updateHint()` | Picks a random app the user is *not* entitled to for the "try something you can't reach" hint — the demo's way of showing a deny. |
| `ensureSession(user, fresh)` | Makes sure a login exists before an attempt (logging in as a demo user if needed), so the story button works from a cold page. |
| `doAttempt(tok, app)` | POSTs `/demo/attempt` and returns the trace. |
| `runAttempt()` | The attempt button: ensures a session, runs the attempt, plays the trace. |
| `runStory()` | "Watch a decision happen": logs in, attempts (allow), revokes, attempts again (deny) — the whole zero-trust story in one click. |

---

## Supporting files

| File | What it is, and why |
|---|---|
| `scripts/gen_certs.sh` | Generates the throwaway demo PKI (CA, PEP cert, PDP server cert, alice/bob client certs) with openssl. Demo-only keys, gitignored — never real credentials. |
| `scripts/enroll_device.sh <CN> <user>` | Enrolls a device: mints a client certificate for the CN (demo CA, 825-day default, `chmod 600` on the key) and registers it to an existing user via `POST /admin/devices`. Refuses a bad CN and an existing certificate before openssl ever runs, so failures are fast and loud. |
| `scripts/demo_e2e.sh` | Proves the five core claims on a live stack (cloaking, policy engine, micro-tunnel, real probe, continuous verification). The script to run before claiming anything works. |
| `scripts/demo_mtls.sh` | Same, with mutual TLS: proves a certificate with no route is still cloaked. |
| `scripts/run_all.sh` | One command to start the local demo: venv + target + PDP + PEP, with Ctrl-C cleanup. `--tls` (or `AEGISX_TLS=1`) serves the PDP over HTTPS with `certs/pdp.crt` and verifies the ready-check against the demo CA; plain HTTP stays the default. |
| `scripts/loadtest_pep.py` | Stdlib-only load test: N concurrent TCP connects to the PEP, reports p50/p99 accept-to-close latency and connections/sec. Measures the real non-blocking PEP — no fake numbers. |
| `examples/target_service.py` | The protected demo app: tiny HTTP service on :8080, plus a `--hold` mode that keeps connections open so revocation of a live tunnel can be observed. |
| `docker-compose.yml` | One `docker compose up` runs Redis + PDP + PEP + target, with healthchecks (`/ready` gates the PDP). |
| `.github/workflows/ci.yml` | CI: pytest (with a Redis service), `mvn package`, `node --check` on the dashboard JS. |
| `docs/architecture.md` | Mermaid + ASCII diagrams, the 60-second data flow, the Redis key schema. |
| `docs/demo-script.md` | A 5-minute spoken demo script for interviews and vivas. |
| `docs/design-notes.md` | The long academic detail moved out of the README (NIST mapping, threat model) — kept, not deleted. |
| `docs/feature-ideas.md` | Every feature idea considered: 13 shipped in batch 2, 9 deliberately deferred (with reasons), 6 proposed next. |
