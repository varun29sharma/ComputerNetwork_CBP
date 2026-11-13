# AegisX 5-minute demo script

For an interview or viva. One terminal, live commands, no slides. Every
expected output below is what the real endpoints return (see
`scripts/demo_e2e.sh` for the automated version of the same story).

## Before you start (30 seconds, off the clock)

```bash
./scripts/run_all.sh        # or: docker compose up
```

Wait for the "AegisX is running" banner. Keep a second terminal ready for the
`curl` commands. If you use Docker, `redis-cli` in the steps below means the
host's `redis-cli` against the published port (:6379).

## 0:00–0:30 — The one-line pitch

> "AegisX is a Zero Trust gateway. There is no VPN to join and no open port to
> find: you authenticate first, the control plane writes a one-person,
> one-app tunnel into Redis, and only then does the gateway let your bytes
> through. Revoke the session and even a tunnel that is already open dies."

Open http://127.0.0.1:8000/ so they can see the dashboard while you talk.

## 0:30–1:00 — Step 1: the cloak (before login)

**Show:** the gateway looks like a closed port to a stranger.

```bash
curl -v http://127.0.0.1:9000/
```

**Say:** "I haven't logged in. Watch what the gateway says."

**Expected:** `Empty reply from server` — the connection is accepted and
closed with zero payload. Same verdict from the probe endpoint:

```bash
curl -s -X POST http://127.0.0.1:8000/demo/probe -H 'Content-Type: application/json' -d '{}'
```

**Expected:** `"allowed":false`, `"reachable":true`,
`"detail":"connection closed before any payload was read (cloaked)"`.

## 1:00–2:00 — Step 2: login, and watch the route appear

**Show:** authentication creates exactly one Redis record — that record *is*
the permission.

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

**Say:** "Alice is a developer, entitled to internal-api. The login returns a
JWT — but the interesting part is what it wrote into Redis."

```bash
redis-cli get route:127.0.0.1
redis-cli ttl route:127.0.0.1
redis-cli hgetall sess:127.0.0.1
```

**Expected:**

```
127.0.0.1:8080
359x            (counts down from 3600 — the tunnel self-destructs)
user / alice, role / developer, app / internal-api, target / 127.0.0.1:8080, ...
```

**Say:** "One key: `route:127.0.0.1`. The control plane never calls the
gateway — this record is the only thing connecting them."

## 2:00–3:00 — Step 3: the same client is now allowed through

**Show:** the identical request from step 1 now reaches the protected app.

```bash
curl http://127.0.0.1:9000/hello
curl -s -X POST http://127.0.0.1:8000/demo/probe -H 'Content-Type: application/json' -d '{}'
```

**Expected:**

```json
{"service": "aegisx-demo-target", "path": "/hello", "peer": "127.0.0.1", "port": 8080}
```

and `"allowed":true`,
`"detail":"proxied through the authorized micro-tunnel: HTTP/1.0 200 OK"`.

**Say:** "Same client, same gateway — the only thing that changed is the
route record. And note the tunnel goes to exactly one app on port 8080, not
a subnet."

*(30-second optional extra — the policy engine denies before any tunnel:)*

```bash
curl -s -X POST http://127.0.0.1:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-dev-pw","app":"metrics-dashboard"}'
```

**Expected:** `403 "not entitled to application: metrics-dashboard"` — and no
route key is written. Denials happen before any tunnel exists.

## 3:00–4:00 — Step 4: revoke, and the cloak comes back

**Show:** revocation is one atomic step, and the token dies immediately.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/logout
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/auth/verify
redis-cli get route:127.0.0.1
curl http://127.0.0.1:9000/
```

**Expected:**

```
{"status":"revoked","jti":"..."}
401 {"detail":"token revoked"}
(nil)                          <- the route key is gone
curl: (52) Empty reply from server
```

**Say:** "Logout denylists the token and deletes the route in one Lua script,
so the gateway can never see a half-revoked session. The token is dead at
once; an already-open tunnel dies at the next 5-second revalidation —
`demo_e2e.sh` step 7 proves that with a held connection."

## 4:00–5:00 — Step 5: the audit trail, and the close

**Show:** both planes write to one append-only stream.

```bash
redis-cli xrevrange audit:events + - COUNT 6
```

**Expected:** recent entries like `login.success`, `tunnel.provisioned`,
`pep.allow`, `pep.deny`, `logout` — each with `client_ip`, `target`
and a timestamp.

**Close with:** "So the whole system is four ideas: authenticate before
connect, one Redis record is the permission, the gateway fails closed and
re-checks every five seconds, and everything is audited. The mTLS version
goes one step further — the tunnel is keyed on your certificate, not your IP
address — `./scripts/demo_mtls.sh` proves that."

## If they ask for more

- **"How fast is the gate?"** — `python3 scripts/loadtest_pep.py -n 1000 -c 200`
  (accept-to-close latency; pre-login, "closed fast, zero bytes" is the cloak
  working, not a failure).
- **"What breaks first?"** — single Redis (fails closed: lockout, not breach);
  demo PKI; polling revalidation. See `docs/architecture.md`.
- **"Show me two users at once"** — `./scripts/demo_mtls.sh`: alice's and
  bob's certificates reach two different apps from the same IP.
