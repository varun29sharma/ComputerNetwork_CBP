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
| `main(args)` | Reads env (PEP port, Redis URL, revalidate seconds), connects to Redis with Lettuce, builds the Netty server bootstrap, binds port 9000. The entry point — everything else hangs off the pipeline it builds. |
| `initChannel(SocketChannel)` | Wires one accepted connection's pipeline: optional TLS handler, then `ZtnaAuthHandler`. Runs once per TCP connection, which is how each connection gets its own auth state. |
| `mtlsEnabled()` | Returns true only when `AEGISX_MTLS=1`, so plain-TCP demos and mTLS demos share one binary. |
| `buildServerSslContext()` | Loads the PEP's cert/key and the CA, requires a client certificate. Exists so the gateway can verify *who* is connecting at the TLS layer, before any app bytes flow. |
| `required(name)` | Reads a mandatory env var or fails fast with a clear error — better than starting half-configured and failing mysteriously mid-demo. |
| `env(name, fallback)` | Reads an env var with a default, so every setting is overridable without recompiling. |

### `ZtnaAuthHandler.java` — the gate (the most important file in the project)

One instance per connection. Its five numbered sections are the story to tell
in an interview: **auth check → Redis lookup → tunnel open → revalidation →
close**.

| Function | What it does, and why |
|---|---|
| `ZtnaAuthHandler(redis, revalidateSeconds)` | Constructor: keeps the async Redis commands and the revalidation interval. The handler needs Redis on every connection, so it is injected once, not looked up per packet. |
| `channelActive(ctx)` — §1 auth check | Fires when a TCP connection opens. With mTLS it waits for the TLS handshake, then reads the client certificate's Common Name as the device identity; without mTLS it uses the remote IP. Runs before any payload is read, so an unauthorized client never gets to send a request. |
| `beginAuthorization(ctx, device)` | Decides the binding (device CN if present, else remote IP) and kicks off the Redis lookup. Separates "who is this" from "are they allowed", so each half is easy to explain. |
| `authorize(ctx, remoteIp, routeKey, rawTarget)` — §2 Redis lookup | The `route:<binding>` GET returned: if a target exists, open the tunnel; if not, deny. This is the allow/deny decision, and it is one Redis read — fast and simple. |
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

The four routers are included here: `routes_auth`, `routes_admin`,
`routes_demo`, `routes_health`. (If an interviewer asks "where is login?" —
`routes_auth.py`, not `main.py`.)

### `deps.py` — auth dependencies

| Function | What it does, and why |
|---|---|
| `current_identity(request, authorization)` | Decodes the Bearer JWT and rejects it if the `jti` is on the Redis denylist. Runs on *every* protected request, so revocation takes effect immediately instead of waiting for expiry. |
| `require_admin(claims)` | Builds on `current_identity` and additionally requires `role == "admin"`. Keeps the admin check in one place instead of repeating it in four endpoints. |

### `routes_auth.py` — login / logout / verify

| Function | What it does, and why |
|---|---|
| `resolve_client_ip(request, body_client_ip)` | Picks the address the session is bound to. Default: the socket's real peer address — the JSON body value is attacker-controlled, so believing it would let anyone ride another host's route. Only with `AEGISX_TRUST_PROXY=1` does it trust `X-Forwarded-For` (first entry), falling back to the body value. |
| `login(body, request)` | The Policy Engine + Administrator: verify credentials → check device registration → check entitlement → check posture → atomic `login_gate` (lockout + rate limits + route write) → mint JWT → store session → audit. The order matters: a denied login must never leave a usable tunnel behind. |
| `logout(request, claims)` | Denylists the token's `jti` and atomically deletes route + session. Finds the route by the *binding in the token*, so a certificate-bound session is torn down even from a different address. |
| `verify(claims)` | Returns 200 only if the token is valid *and* not denylisted — the continuous-verification probe the UI and tests use. |

### `routes_admin.py` — the SOC console

| Function | What it does, and why |
|---|---|
| `admin_sessions(request, claims)` | Lists every live tunnel with its identity — the "who is connected right now" view. |
| `admin_revoke(body, request, claims)` | Force-revokes a session by device or IP: looks up the session, denylists its `jti`, deletes route + session. The admin never needs the victim's token. |
| `admin_audit(request, limit, claims)` | Returns the recent audit trail (Redis Stream) — every allow/deny decision in one place. |
| `admin_apps(claims)` | Returns the protected apps and their posture rules — the policy-as-code view. |

### `routes_demo.py` — probe, attempt, metrics, dashboard feed

| Function | What it does, and why |
|---|---|
| `_app_row(name, target)` | One app's public description (name, target, posture rules) — shared by `/apps` and `/admin/apps` so they cannot drift apart. |
| `metrics(request)` | Aggregates the PDP + PEP counters from Redis into one JSON object for the dashboard. |
| `apps()` | Public list of protected apps, so the UI can offer them in the login form without needing a login first. |
| `_cert_paths(name)` | Resolves a demo certificate name to files inside `certs/`, refusing anything that escapes the directory — a demo endpoint must not become an arbitrary file reader. |
| `_cert_common_name(path)` | Reads the CN out of a PEM certificate with the stdlib only — no extra dependency for a demo helper. |
| `_available_certs()` | Lists the demo client certificates (excluding `ca` and `pep`) for the UI's cert selector. |
| `demo_probe(body)` | POST `/demo/probe`: opens a **real TCP connection** to the PEP (optionally with a client cert) and reports what the gate decided. The demo's proof is a live socket, not a prediction. |
| `_run_probe(addr, cert_name)` | The shared socket logic behind `/demo/probe` and `/demo/attempt`, so both exercise one identical enforcement path. |
| `_delivered_port(payload)` | Figures out which app instance answered, from the hold banner or the JSON `"port"` field — proves *which* app the tunnel reached. |
| `_app_for_port(port)` | Maps a port back to an app name via `APP_TARGETS`. |
| `demo_attempt(body, request, claims)` | Traces one "access that application" attempt gate by gate (identity → entitlement → authorization record → real TCP through the PEP) and reports the final decision, the reason, and which app physically answered. |
| `dashboard_state(request)` | The demo-only live feed: routes, denylist, rate limits, sessions, lockouts, audit, metrics, apps, users, certs. One endpoint, so the UI polls once instead of ten times. |

### `routes_health.py` — liveness and readiness

| Function | What it does, and why |
|---|---|
| `health(request)` | `/health`: 200 if Redis answers a ping. Liveness — "is the process up". |
| `ready(request)` | `/ready`: 200 only if Redis pings OK **and** at least one `users:<name>` record exists. Without seeded users every login would 401, so the instance must not receive traffic yet. |

### `config.py` — every knob in one place

Plain constants read from env with defaults: `REDIS_URL`, `JWT_SECRET`,
`ACCESS_TOKEN_TTL_SECONDS` (3600), `ROUTE_TTL_SECONDS` (3600),
`POSTURE_STRICT`, `PEP_PROBE_ADDR` (`127.0.0.1:9000`), `CERTS_DIR`. One file
so a reviewer can see every setting without hunting.

### `identity.py` — the demo directory (stand-in for an IdP)

| Function | What it does, and why |
|---|---|
| `user_key(username)` | Builds the `users:<name>` Redis key. Key-building lives in one place so a typo cannot create a second, invisible namespace. |
| `hash_password(password, salt)` | PBKDF2-HMAC-SHA256 with a random salt — passwords are never stored or compared in plaintext, even in a demo. |
| `seed_users(redis)` | Writes the three demo users (alice, bob, admin) at startup if missing. Idempotent, so restarts are safe. |
| `get_user(redis, username)` | Reads one user record from Redis. |
| `verify_credentials(redis, username, password)` | Constant-time password check; returns the user or `None`. Runs a dummy hash for unknown users so the timing does not reveal whether an account exists. |
| `_hash_password_dummy(password)` | The dummy hash above — burns the same time as a real check. |
| `choose_app(user, requested)` | Picks the app: the requested one if the user is entitled, else the user's first entitled app, else raises `PolicyError`. One function owns the entitlement decision. |
| `registered_device(user)` | Returns the certificate identity registered to a user (e.g. `device:alice`). |
| `device_matches(user, device)` | True only if the asserted device is the one registered to that user — stops one user riding another's certificate. |
| `directory_summary()` | Public, password-free view of the directory for the dashboard. |
| `evaluate_posture(app, posture, strict)` | Returns a list of failed posture rules for an app (e.g. firewall off). Empty list = pass. Strict mode also fails on *missing* claims — fail closed. |

### `security.py` — JWT minting and checking

| Function | What it does, and why |
|---|---|
| `mint_token(username, role, client_ip, device, binding)` | Signs a JWT (HS256) with `sub`, `role`, `client_ip`, `device`, `binding`, a unique `jti`, and a 1-hour expiry. The `jti` is what makes revocation possible — without it a token is un-revocable until expiry. |
| `decode_token(token)` | Verifies the signature and expiry and returns the claims. Raises on anything invalid, so callers never have to check twice. |

### `state.py` — all Redis access (the only module that talks to Redis)

Key builders (`binding`, `split_binding`, `route_key`, `session_key`,
`denylist_key`, `rate_limit_key`, `ip_rate_key`, `fails_key`, `lock_key`):
each builds one key name. Centralising them means a rename is one edit and a
typo is impossible to hide.

| Function | What it does, and why |
|---|---|
| `connect()` | Opens the async Redis client from `REDIS_URL`. One connection, shared by the app. |
| `audit(redis, event, **fields)` | Appends one event to the `audit:events` Redis Stream. A stream (not a list) keeps events ordered with timestamps. |
| `recent_audit(redis, count)` | Reads the newest audit events, newest first, for the dashboard and `/admin/audit`. |
| `set_session(redis, binding, fields, ttl)` | Stores the session hash (`sess:<binding>`) with the same TTL as the route, so the two expire together and can never disagree. |
| `list_sessions(redis)` | Scans `sess:*` and returns every live session for the admin console. |
| `login_gate(redis, username, client_ip, target, binding)` | Runs `LOGIN_LUA` — one atomic script that checks the lockout, bumps the per-user and per-IP rate counters, and writes the route. Atomic because "check then write" in two steps has a race: two parallel logins could both pass the check. |
| `revoke(redis, jti, binding, remaining_ttl)` | Runs `LOGOUT_LUA` — one atomic script that denylists the `jti` and deletes route + session. Atomic so a revoke can never leave half the state behind. |
| `is_denied(redis, jti)` | True if the `jti` is on the denylist — the check `current_identity` runs on every request. |
| `incr_counter(redis, name)` | Bumps a counter (`logins:ok`, `logins:denied`, `admin:revocations`) for `/metrics`. |
| `metrics(redis)` | Reads all counters (PDP + PEP) into one dict. |

The two Lua scripts (`LOGIN_LUA`, `LOGOUT_LUA`) exist for one reason: Redis
runs a Lua script atomically, so a check-and-write that must not interleave
with another request is safe without locks.

### `schemas.py` — request/response shapes

Pydantic models (`LoginRequest`, `LoginResponse`, `ProbeRequest`,
`ProbeResponse`, `AttemptRequest`, `AttemptResponse`, `AdminRevokeRequest`,
`RevocationResponse`, `VerifyResponse`, `AttemptStage`). They validate every
request body and document the API — FastAPI turns them into the `/docs` page
for free.

---

## Part 3 — Dashboard, `control-plane/app/static/`

### `index.html` — structure only

Sections in order: header (title + status pill), login card, gateway probe
card, attempt visualization (`flowviz` SVG + trace), enforcement counters,
live sessions, Redis inspector, audit trail, admin console. Endpoint paths
are shown as small mono labels under each panel heading, so the page itself
teaches the API.

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
| `refreshState()` | Polls `/dashboard/state` and re-renders everything. One poll, one render pass. |
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
| `scripts/gen_certs.sh` | Generates the throwaway demo PKI (CA, PEP cert, alice/bob client certs) with openssl. Demo-only keys, gitignored — never real credentials. |
| `scripts/demo_e2e.sh` | Proves the five core claims on a live stack (cloaking, policy engine, micro-tunnel, real probe, continuous verification). The script to run before claiming anything works. |
| `scripts/demo_mtls.sh` | Same, with mutual TLS: proves a certificate with no route is still cloaked. |
| `scripts/run_all.sh` | One command to start the local demo: venv + target + PDP + PEP, with Ctrl-C cleanup. |
| `scripts/loadtest_pep.py` | Stdlib-only load test: N concurrent TCP connects to the PEP, reports p50/p99 accept-to-close latency and connections/sec. Measures the real non-blocking PEP — no fake numbers. |
| `examples/target_service.py` | The protected demo app: tiny HTTP service on :8080, plus a `--hold` mode that keeps connections open so revocation of a live tunnel can be observed. |
| `docker-compose.yml` | One `docker compose up` runs Redis + PDP + PEP + target, with healthchecks (`/ready` gates the PDP). |
| `.github/workflows/ci.yml` | CI: pytest (with a Redis service), `mvn package`, `node --check` on the dashboard JS. |
| `docs/architecture.md` | Mermaid + ASCII diagrams, the 60-second data flow, the Redis key schema. |
| `docs/demo-script.md` | A 5-minute spoken demo script for interviews and vivas. |
| `docs/design-notes.md` | The long academic detail moved out of the README (NIST mapping, threat model) — kept, not deleted. |
