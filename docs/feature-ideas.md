# AegisX feature ideas — shipped, deferred, proposed

Every idea considered for the gateway, with what it is, why it matters, how
big it is, and the verdict. **Shipped** means it is in the code and tested;
**deferred** means deliberately not built, with the reason; **proposed**
means worth building next. Effort: **S** = hours, **M** = a day or two,
**L** = several days or new infrastructure.

28 ideas: 13 shipped in batch 2 (Nov 2026), 9 deferred, 6 proposed.

---

## Shipped in batch 2

### 1. Policy-as-data + hot reload — ✅ shipped
**What:** app policy (target, posture, hours, TTL, enabled) lives in the
Redis hash `policy:apps`, edited via `GET/PUT/DELETE /admin/policy`, with a
dashboard editor. **Why:** changing a rule used to mean editing Python
constants and restarting; now an admin flips a rule and the next login is
judged by it. **Effort:** M. **Verify:** `tests/test_policy_data.py`;
PUT a posture rule, then log in and watch 200 flip to 403 with no restart.

### 2. Time rules + per-app session TTL — ✅ shipped
**What:** `allowed_hours` (`"HH:MM-HH:MM"`, empty = always) denies logins
outside the window, and `session_ttl_seconds` (60–86400) sets the route +
session lifetime per app; the JWT lifetime stays the global 3600 s.
**Why:** business-hours apps and short-lived tunnels are the two most common
real policy asks, and both are one field each once policy is data.
**Effort:** S. **Verify:** `tests/test_time_rules.py`.

### 3. TLS on the control plane — ✅ shipped
**What:** a dedicated PDP server certificate (`certs/pdp.crt`, CN
`localhost`, SANs `localhost`/`127.0.0.1`, signed by the demo CA);
`./scripts/run_all.sh --tls` or `AEGISX_TLS=1` serves the PDP over HTTPS.
Plain HTTP stays the default. **Why:** dashboard logins otherwise cross the
wire in cleartext on a shared network. **Effort:** S. **Verify:**
`curl --cacert certs/ca.crt https://127.0.0.1:8000/health`.

### 4. Device enrollment + certificate revocation — ✅ shipped
**What:** `POST /admin/devices` registers a certificate CN to a user,
`POST /admin/devices/revoke` writes `cert:deny:<CN>` (24 h TTL) and revokes
the CN's live sessions, `scripts/enroll_device.sh <CN> <user>` mints the
cert and registers it in one step, and the PEP checks `cert:deny` at
tunnel-open. **Why:** revoking sessions was possible; revoking the
*credential itself* was not — a stolen cert kept working after its sessions
died. **Effort:** M. **Verify:** `tests/test_admin_ops.py` (PDP side);
the PEP-side check is **live-unverified** (Java TCP is blocked in the
build VM — verify with `scripts/demo_mtls.sh` plus a revoked cert).

### 5. Admin user management — ✅ shipped
**What:** `POST /admin/users` (PBKDF2-hashed password, role, entitlements,
optional device), `POST /admin/users/{name}/disable` (also revokes the
user's live sessions) and `/enable`. A disabled login returns the same 401
as a wrong password, so probing cannot distinguish them. **Why:** the
directory was seed-only; an operator could not add or remove a person
without editing code and restarting. **Effort:** S.
**Verify:** `tests/test_admin_ops.py`.

### 6. Lockout management — ✅ shipped
**What:** `GET /admin/lockouts` lists locked users (`lock:*`) and
rate-limited IPs (`ipl:*`) with remaining seconds; `POST /admin/unlock`
clears either or both. Dashboard table with one-click unlock. **Why:**
lockout used to be a 5-minute wait with no operator override — the SOC
could see the lock in Redis but had no API to clear it. **Effort:** S.
**Verify:** `tests/test_admin_ops.py`.

### 7. Emergency lockdown — ✅ shipped
**What:** `POST/GET /admin/lockdown` flips the `admin:lockdown` flag. While
on, every login (password and service-key) is 403 and every live session is
revoked, so open tunnels die at the next PEP revalidation; the dashboard
shows a banner. **Why:** incident response needs one switch, not a revoke
per session. **Effort:** S. **Verify:** `tests/test_admin_ops.py`.
**Caveat:** the banner reads the flag from `/dashboard/state`, which
carries it only in the FULL view — with `AEGISX_DASHBOARD_AUTH=1` and no
admin token, the banner will not show.

### 8. Audit export — ✅ shipped
**What:** `GET /admin/audit/export?format=json|csv` downloads the audit
trail (up to 500 events) as a file, and audits the export itself.
**Why:** the trail lived only in a Redis Stream — an auditor could not take
it offline, and a stream capped at 10,000 entries is not an archive.
**Effort:** S. **Verify:** `tests/test_admin_ops.py`.

### 9. Prometheus metrics — ✅ shipped
**What:** `GET /metrics/prometheus` re-renders the same counters `/metrics`
returns as JSON (7 counters, 2 gauges) in Prometheus text format, plus an
`aegisx_uptime_seconds` gauge. **Why:** JSON metrics need a custom
collector; Prometheus text is the standard scraper format, so the gateway
plugs into real monitoring with no extra tooling. **Effort:** S.
**Verify:** `tests/test_prometheus.py`.

### 10. Dashboard auth flag — ✅ shipped
**What:** `AEGISX_DASHBOARD_AUTH=1` makes `/dashboard/state` redact
sensitive fields (sessions, audit, Redis keys, users, lockdown flag)
unless the request carries a valid admin token; counters stay public.
Default off, so the demo still works with no setup; the JS sends the admin
token once the admin has authenticated. **Why:** the live feed was fully
open by design — this closes the biggest honest limitation without breaking
the zero-setup demo. **Effort:** S. **Verify:**
`tests/test_dashboard_auth.py`.

### 11. PEP reachability in the dashboard feed — ✅ shipped
**What:** `/dashboard/state` now carries `pep_reachable` and
`pep_latency_ms`, from a plain TCP connect to the PEP with a 0.3 s timeout
(no payload — the PEP cloaks, so bytes would prove nothing).
**Why:** the dashboard showed PDP state only; a dead PEP looked identical
to a healthy one until a probe failed. **Effort:** S. **Verify:**
`tests/test_pep_reachable.py`. **Caveat:** the fields are in the feed but
the UI does not render them yet — no PEP status widget on the page.

### 12. PEP readiness gate — ✅ shipped
**What:** `AEGISX_PEP_REQUIRE_READY=1` makes the PEP poll the PDP's
`/ready` endpoint before binding (10 attempts, 1–5 s backoff, 2 s
timeouts); if the PDP never reports ready, the PEP exits without
listening. Default off. **Why:** a PEP that cannot reach its PDP can only
cloak everyone — better to not listen at all than to look like a dead
port. **Effort:** S. **Verify:** start the PEP with Redis down and the
flag on; it must exit(1) without binding. **Live-unverified** in the
build VM (Java TCP blocked).

### 13. Service accounts (stretch) — ✅ shipped
**What:** `POST /admin/service-accounts` creates a machine identity for
one app (API key shown once, only its SHA-256 stored); `POST /auth/service`
exchanges the key for a JWT with `role=service`, bound to that one app.
**Why:** services are not humans — they should not share a demo user's
password, and a key scoped to one app limits blast radius. **Effort:** M
(~160 non-blank lines including its 2 tests — slightly over the ~150-line
guide, which is fine: the exchange reuses the login gate, lockdown check
and time-window code rather than duplicating them). **Verify:**
`tests/test_service_accounts.py`.

---

## Deferred — deliberately not built

### 14. OIDC / Keycloak as the real IdP — ⏸ deferred
**What:** replace `identity.verify_credentials` with an OIDC
authorization-code flow against a local Keycloak/Dex. **Why not yet:** it
needs an IdP container, a redirect flow and group-claim mapping — several
days and new infrastructure, for a demo whose seam (one function) is
already clean. The demo directory is the honest stand-in until then.
**Effort:** L. (ROADMAP 3.3)

### 15. Per-app L7 protocol awareness — ⏸ deferred
**What:** sniff the first bytes of a tunnel and allow only the protocols an
entitlement permits (e.g. HTTP/1.1, not SSH, through an HTTP-only tunnel).
**Why not yet:** the PEP is L4 by design and the project explicitly does
not do payload inspection (ROADMAP non-goal: no WAF/DPI); per-protocol
parsers risk breaking binary protocols and add a whole new attack surface.
**Effort:** L. (ROADMAP 3.4)

### 16. Multi-PEP topology — ⏸ deferred
**What:** two PEPs (edge + app-side) or one PEP per app, so the demo stops
collapsing every role onto `127.0.0.1`. **Why not yet:** it is a topology
and routing project (compose networking, per-app PEP config), not a
feature; the single-PEP enforcement path is the thing being demonstrated.
**Effort:** M. (ROADMAP 2.4)

### 17. Revocation bus (Redis pub/sub) — ⏸ deferred
**What:** publish revocations so the PEP closes tunnels in milliseconds
instead of at the next 5 s revalidation poll. **Why not yet:** 5 s is fast
enough for a demo and polling is the safety net anyway — a bus adds a
second delivery path that must stay in sync with the poll, for a gain of
seconds, not correctness. **Effort:** M. (ROADMAP Phase 4)

### 18. Redis Sentinel / Cluster — ⏸ deferred
**What:** HA for the state broker so a Redis outage is not a global
lockout. **Why not yet:** an ops/deployment story, not a code feature —
and the `sess:*` scans would need a set index first, since scans are not
cluster-friendly. The PEP already fails closed, so the failure mode is
downtime, not a breach. **Effort:** L. (ROADMAP Phase 4)

### 19. SPIFFE / SPIRE workload identity — ⏸ deferred
**What:** short-lived SVIDs instead of static client certificates.
**Why not yet:** needs a SPIRE server plus an agent per workload — heavy
infrastructure for a demo PKI that already works, and service accounts
(idea 13) cover the machine-identity need more simply for now.
**Effort:** L. (ROADMAP Phase 4)

### 20. eBPF / XDP default-drop — ⏸ deferred
**What:** move the deny decision into the NIC driver for line-rate DDoS
immunity. **Why not yet:** needs a Linux host with privileges; the
build/demo environment is a VM/laptop, and it is the report's headline
stretch goal, deliberately out of scope for this demo. **Effort:** L.
(ROADMAP Phase 4)

### 21. WebSocket live updates — ⏸ deferred
**What:** push dashboard state over a WebSocket instead of polling
`/dashboard/state` every 2 s. **Why not yet:** polling is honest and
simple — the page never claims state it has not just read — and a socket
adds connection state to a deliberately stateless demo page. The 2 s lag
is invisible in a demo. **Effort:** M.

### 22. IP geo-allowlist — ⏸ deferred
**What:** allow/deny logins by the source IP's country, via a GeoIP DB.
**Why not yet:** it points the wrong way — the project moved identity from
IP addresses to certificate CNs precisely so identity travels and IPs do
not anchor policy; a geo rule would re-anchor it, and it needs a GeoIP
database the demo does not have. **Effort:** M.

---

## Proposed — worth building next

### 23. Per-user "my sessions" view — 💡 proposed
**What:** a `GET /auth/sessions` endpoint (any authenticated user) listing
only that user's live sessions, plus a dashboard panel with a per-session
"revoke" button. **Why:** users currently cannot see or kill their own
other sessions — only an admin can. It is the single most user-visible
missing piece after admin user management. **Effort:** S.

### 24. Token refresh endpoint — 💡 proposed
**What:** `POST /auth/refresh` exchanges a still-valid JWT for a fresh one
(same `jti` lineage, old token denylisted) without re-entering the
password. **Why:** a 1-hour token with no refresh forces a full re-login
mid-demo and mid-work; refresh keeps sessions alive without weakening
revocation, since the old `jti` dies on refresh. **Effort:** S.

### 25. Audit webhook — 💡 proposed
**What:** an admin-configured HTTPS endpoint that receives each audit event
as it is written (fire-and-forget, with a retry queue). **Why:** export
(idea 8) is pull-based — a SIEM integration wants push. The stream already
holds every event; the webhook is a forwarder on top of it. **Effort:** M.

### 26. TOTP second factor — 💡 proposed
**What:** optional per-user TOTP (RFC 6238, `pyotp`-free: the stdlib can do
HMAC-SHA1 + base32) checked at login after the password, with a
`require_mfa` flag per app in the policy record. **Why:** it is the
remaining half of ROADMAP 3.2 — time rules and TTLs shipped, MFA did not —
and it is the most commonly asked "what about MFA?" interview answer.
**Effort:** M.

### 27. Policy dry-run simulator — 💡 proposed
**What:** `POST /admin/policy/dry-run` takes a user, app and posture and
returns the verdict the *proposed* policy would give, without writing
anything. **Why:** admins currently edit live rules and discover mistakes
from the next denied login; a dry run turns policy editing from
trial-and-error into a checkable change. **Effort:** S.

### 28. Backup / restore of policy + users — 💡 proposed
**What:** `GET /admin/backup` dumps `policy:apps` + `users:*` (+ service
accounts) as JSON, `POST /admin/restore` reloads it. **Why:** policy is now
data in Redis, and Redis here runs without persistence — one restart wipes
every admin edit. A backup file is the cheapest durability until real
Redis persistence lands. **Effort:** S.

---

## Also considered, not written up

- **Per-user IP allowlist** — overlaps the deferred geo-allowlist (idea 22)
  and re-anchors identity to IPs; skipped for the same reason.
- **Password expiry / rotation** — belongs to the real IdP (idea 14), not
  to the demo directory; building it here would be throwaway code.
- **Structured JSON logging** — small, uncontroversial, just not picked for
  this batch; the print-style logs are fine at demo scale.
