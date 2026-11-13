# AegisX — run doc

The previewed server is the **control plane** (FastAPI PDP). It serves the
dashboard/explainer UI at `/`, the raw interactive API at `/docs` (Swagger), a
demo-only live state feed at `/dashboard/state`, and `/metrics`.

For the full experience the dashboard needs the other two processes: the Netty
**PEP** (:9000) for the real TCP probe, and a **protected target app** (:8080).

## Reproduce the uncommitted artifacts

No env files to copy — all config is env vars with safe local defaults
(`AEGISX_REDIS_URL`, `AEGISX_JWT_SECRET`, `AEGISX_TOKEN_TTL`,
`AEGISX_ROUTE_TTL`, `AEGISX_LOGIN_RATE_LIMIT`, `AEGISX_LOCKOUT_SECONDS`,
`AEGISX_POSTURE_STRICT`, `AEGISX_PEP_PROBE_ADDR`, `AEGISX_REVALIDATE_SECONDS`).

1. Python deps (project venv, from `control-plane/requirements.txt`):

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r control-plane/requirements.txt
   ```

2. Redis state store on :6379 (installed via `brew install redis`; persistence
   disabled for the local demo):

   ```bash
   redis-server --port 6379 --save "" --appendonly no --daemonize yes
   redis-cli ping   # expect PONG
   ```

3. The Netty PEP jar (`brew install maven`):

   ```bash
   (cd data-plane && mvn package)   # -> data-plane/target/aegisx-ztna-proxy.jar
   ```

4. Local PKI for the mTLS demo (throwaway; `certs/` is gitignored):

   ```bash
   ./scripts/gen_certs.sh           # add --force to regenerate
   ```

## Run the server (previewed)

```bash
cd control-plane && exec ../.venv/bin/python -m uvicorn app.main:app \
  --host 127.0.0.1 --port 8000 --log-level info
```

Detached start (survives tool-call cleanup on this Mac): plain `nohup ... &`
from the command runner gets its process group reaped, and `launchctl submit`
jobs are TCC-blocked from reading ~/Desktop (`Operation not permitted`), so
wrap the launch in `os.setsid()` and health-check inside the same command:

```bash
{ nohup /bin/sh -c 'exec /usr/bin/python3 -c "import os,sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])" \
    /Users/sudha/Desktop/CN_Project/.venv/bin/python \
    /Users/sudha/Desktop/CN_Project/.venv/bin/uvicorn \
    --app-dir /Users/sudha/Desktop/CN_Project/control-plane app.main:app \
    --host 127.0.0.1 --port 8000 --log-level info' \
  > "/Users/sudha/Desktop/CN_Project/.freebuff/preview-v2.log" 2>&1 < /dev/null & echo "pid=$!"; disown; }
# then poll http://127.0.0.1:8000/health to 200 in the SAME command
```

The same `os.setsid()` wrapper is what made the PEP and target service survive:

```bash
# protected target app (--hold keeps a connection open so revocation is visible)
{ nohup /bin/sh -c 'exec /usr/bin/python3 -c "import os,sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])" \
    /Users/sudha/Desktop/CN_Project/.venv/bin/python \
    /Users/sudha/Desktop/CN_Project/examples/target_service.py --port 8080 --hold' \
  > "$PWD/.freebuff/target-v2.log" 2>&1 < /dev/null & disown; }

# data plane (PEP) on :9000
{ nohup /bin/sh -c 'exec /usr/bin/python3 -c "import os,sys; os.setsid(); os.execv(sys.argv[1], sys.argv[1:])" \
    /usr/bin/java --enable-native-access=ALL-UNNAMED \
    -jar /Users/sudha/Desktop/CN_Project/data-plane/target/aegisx-ztna-proxy.jar' \
  > "$PWD/.freebuff/pep-v2.log" 2>&1 < /dev/null & disown; }
```

- Health check: `curl -sf http://127.0.0.1:8000/health`
- Dashboard (main UI): http://127.0.0.1:8000/
- Interactive API: http://127.0.0.1:8000/docs · metrics: `/metrics`
- Demo users: `alice` / `alice-dev-pw` (developer → internal-api, registered
  device `alice`), `bob` / `bob-analyst-pw` (analyst → metrics-dashboard,
  registered device `bob`), `admin` / `admin-console-pw` (administrator —
  authenticates, gets **no** tunnel).
- Login must send `"client_ip"` in the payload (demo shortcut) — use
  `127.0.0.1` to line up with the PEP and target on this host.
- Send `"device": "<CN>"` to bind the session to a certificate; it must be the
  CN registered to that identity (the demo certificates use CN = username).
- The previewed PEP on :9000 runs with `AEGISX_MTLS=1`, so the dashboard's probe
  needs a certificate selected to be allowed (start it without `AEGISX_MTLS` for
  the plaintext, source-address-keyed behaviour).
- Tests need `node` for the dashboard JavaScript parse check (that test skips
  without it); a syntax error in `index.html` otherwise passes every marker
  assertion while breaking every button in the browser. `node --check` on a
  temp copy of the inline script catches it.

### What the dashboard actually drives

| UI action | Real call | What to watch |
|---|---|---|
| Log in & open tunnel | `POST /auth/login` (with `app` + `posture` + `device`) | gateway flips to TUNNEL OPEN, JWT decodes, `route:device:<CN>` appears with a TTL bar, session row appears |
| Device identity field | `POST /auth/login` with `device` | route is keyed by the certificate CN; asserting a CN not registered to that identity is a 403 |
| Probe the gateway over real TCP | `POST /demo/probe` (optional `cert`) | an actual TCP connection to the PEP: ALLOW with the target banner, the cloak, or a refused handshake |
| Ask for another user's app | `POST /auth/login` with `app` | 403 "not entitled", no route written |
| Turn posture to `false` | `POST /auth/login` with posture | 403 "device posture denied" |
| Log out & revoke everything | `POST /auth/logout` | jti denylisted, route gone, PEP kills open tunnels within one revalidation interval |
| Admin console sign-in | `POST /auth/login` as admin | admin-role token; `/admin/sessions` + `/admin/apps` load |
| Revoke (in the session table) | `POST /admin/revoke` (by `device`, or `client_ip`) | session disappears, gateway returns to CLOAKED, "admin revokes" counter increments |

## Full end-to-end stack (CLI, not part of the preview)

`./scripts/demo_e2e.sh` starts target app :8080 (holding mode) + control plane
:8000 + PEP :9000 and proves cloak → policy denials → micro-tunnel → real probe
→ **revocation killing an already-open tunnel** → cloak. It stops the processes
it starts, so run it with custom ports while the preview is up:

```bash
CP_PORT=8010 PEP_PORT=9010 ./scripts/demo_e2e.sh    # ALL CHECKS PASSED
```

`./scripts/demo_mtls.sh` starts the PEP with `AEGISX_MTLS=1` and proves that
**authorization is bound to the certificate, not the address**: three
connections from the same IP 127.0.0.1 — no certificate (rejected at the
handshake), alice's certificate (ALLOW), bob's certificate (DENY,
`no-device-route`) — plus a 403 when alice claims bob's identity, and a
certificate-bearing `/demo/probe`:

```bash
CP_PORT=8010 PEP_PORT=9011 ./scripts/demo_mtls.sh   # ALL MTLS CHECKS PASSED
```

## Tests

```bash
(cd control-plane && ../.venv/bin/python -m pytest tests/ -q)   # 47 tests
```

Requires Redis. The suite clears every AegisX-namespaced key before each test
(`route:`, `sess:`, `jwt:deny:`, `login:rl:`, `ipl:`, `fails:`, `lock:`,
counters, `audit:events`) — if a new namespace is added to the app, add it to
`KEY_PREFIXES`/`KEY_EXACT` in `tests/conftest.py` or tests will leak state.
