// AegisX dashboard — plain JavaScript, no framework, no build step.
// Each function does one thing. Comments explain *why*, not *what*.
"use strict";

const $ = (id) => document.getElementById(id);
const ROUTE_TTL = 3600; // seconds a route lives in Redis; also the TTL bar scale
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let token = null;      // the demo user's JWT (null = logged out)
let adminToken = null; // the admin console's JWT (null = not authenticated)
let ENTITLED = {};     // username -> { apps: [...] }, filled from /dashboard/state
let POLICY = {};       // app name -> live policy record, filled from /admin/policy
let lockdownOn = false; // true while /dashboard/state reports lockdown
let fzBusy = false;    // true while the open-then-revoke story is playing

const PW = { alice: "alice-dev-pw", bob: "bob-analyst-pw", admin: "admin-console-pw" };
// Each demo identity is registered to a certificate with the same Common Name
// (scripts/gen_certs.sh), so choosing an identity proposes its device too.
const DEVICE = { alice: "alice", bob: "bob", admin: "" };

// ---- small helpers -------------------------------------------------------

function esc(value) {
  // Values rendered into the page come from the server; escape them so a
  // hostile username or app name can never inject markup.
  return String(value == null ? "" : value).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
}

function toast(msg, kind) {
  const el = document.createElement("div");
  el.className = "toast " + (kind || "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function log(msg, cls) {
  // Newest first: the event log reads like a terminal tail.
  if ($("log").querySelector(".note")) $("log").innerHTML = "";
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = "<time>" + new Date().toLocaleTimeString("en-GB", { hour12: false }) +
    '</time><span class="' + (cls || "info") + '">' + msg + "</span>";
  $("log").prepend(line);
}

function decodeJwt(t) {
  // JWTs are base64url, not base64: translate the alphabet before decoding.
  const payload = t.split(".")[1];
  return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
}

function eventClass(ev) {
  // Audit events are words; the class only picks white vs grey text.
  if (!ev) return "ev-info";
  if (ev.indexOf("denied") >= 0 || ev.indexOf("deny") >= 0 || ev.indexOf("revoke") >= 0) return "ev-deny";
  if (ev.indexOf("success") >= 0 || ev.indexOf("provisioned") >= 0 || ev.indexOf("allow") >= 0) return "ev-ok";
  if (ev.indexOf("ratelimit") >= 0 || ev.indexOf("locked") >= 0 || ev.indexOf("fail") >= 0) return "ev-warn";
  return "ev-info";
}

// ---- live state ----------------------------------------------------------

// One poll carries everything the page shows: routes, sessions, audit,
// metrics, apps, certs. Polling every 2s keeps the demo honest — the page
// never claims state it has not just read from the server.
async function refreshState() {
  let s;
  try {
    // An admin token unlocks the sensitive fields when the dashboard-auth
    // flag is on; without one the request goes out exactly as before.
    const headers = {};
    if (adminToken) headers.Authorization = "Bearer " + adminToken;
    s = await (await fetch("/dashboard/state", { cache: "no-store", headers })).json();
  } catch (e) {
    $("hero-redis").textContent = "unreachable";
    return;
  }

  // When the dashboard-auth flag is on, an unauthenticated request gets
  // counters only — default the withheld lists instead of crashing on them.
  s.routes = s.routes || [];
  s.sessions = s.sessions || [];
  s.audit = s.audit || [];
  s.denylisted = s.denylisted || [];
  s.rate_limits = s.rate_limits || [];
  s.lockouts = s.lockouts || [];
  s.apps = s.apps || [];
  s.certs = s.certs || [];
  setLockdownUI(s.lockdown === true);

  $("hero-redis").textContent = "connected";
  $("hero-tunnels").textContent = s.routes.length;
  $("hero-denies").textContent = s.metrics.pep_deny_total;
  $("hero-posture").textContent = s.posture_strict ? "fail-closed" : "claims optional";

  renderMetrics(s.metrics);
  fillSelects(s);
  renderRedis(s);
  renderSessions(s.sessions);
  renderAudit(s.audit);

  // A device-bound session is matched on its certificate identity; a plaintext
  // session on its source address. They are different authorization namespaces.
  const dev = $("device").value.trim();
  const ip = $("ip").value.trim();
  const mine = dev
    ? s.routes.find((r) => r.device === dev)
    : s.routes.find((r) => r.client_ip === ip && !r.device);
  setGateway(!!mine, mine);
}

function renderMetrics(m) {
  $("m-allow").textContent = m.pep_allow_total;
  $("m-deny").textContent = m.pep_deny_total;
  $("m-revoked").textContent = m.pep_revoked_total;
  $("m-active").textContent = m.pep_active_tunnels;
  $("m-logins").textContent = m.logins_ok_total;
  $("m-logins-bad").textContent = m.logins_denied_total;
  $("m-admin").textContent = m.admin_revocations_total;
}

// Fill the app/cert dropdowns once, from the server's own view of policy —
// never hardcode the app list, or the demo drifts from the backend.
function fillSelects(s) {
  if (!$("app").dataset.filled && s.apps.length) {
    $("app").innerHTML = '<option value="">(first entitled)</option>' +
      s.apps.map((a) => '<option value="' + a.name + '">' + a.name + " → " + a.target + "</option>").join("");
    $("app").dataset.filled = "1";
  }
  if (s.users) ENTITLED = s.users;
  if (!$("att-app").dataset.filled && s.apps.length) {
    $("att-app").innerHTML = s.apps.map((a) =>
      '<option value="' + a.name + '">' + a.name + " → " + a.target + "</option>").join("");
    $("att-app").dataset.filled = "1";
    pickSurpriseApp();
    updateHint();
  }
  if (!$("probe-cert").dataset.filled && s.certs.length) {
    $("probe-cert").innerHTML = '<option value="">none — plaintext connection</option>' +
      s.certs.map((c) => '<option value="' + c + '">' + c + "</option>").join("");
    $("probe-cert").dataset.filled = "1";
  }
}

function renderRedis(s) {
  const rows = [];
  for (const r of s.routes) {
    rows.push('<tr><td class="k">' + r.key + '</td><td class="v">' + r.target + "</td><td>" +
      (r.device ? "cert " + r.device : "ip " + r.client_ip) + "</td><td>" + r.ttl + "s</td>" +
      '<td><div class="ttlbar"><i style="width:' + Math.max(0, (r.ttl / ROUTE_TTL) * 100) + '%"></i></div></td></tr>');
  }
  for (const d of s.denylisted) {
    rows.push('<tr><td class="k">' + d.key.slice(0, 26) + '…</td><td class="muted">REVOKED</td><td></td><td>' + d.ttl + "s</td>" +
      '<td><div class="ttlbar"><i class="revoked" style="width:' + Math.max(0, (d.ttl / ROUTE_TTL) * 100) + '%"></i></div></td></tr>');
  }
  for (const l of s.rate_limits) {
    rows.push('<tr><td class="k">' + l.key + '</td><td class="muted">' + l.attempts + " attempts (" + l.scope + ")</td><td></td><td>" + l.ttl + "s</td><td></td></tr>");
  }
  for (const l of s.lockouts) {
    rows.push('<tr><td class="k">lock:' + l.username + '</td><td class="muted">LOCKED OUT</td><td></td><td>' + l.ttl + "s</td><td></td></tr>");
  }
  $("redis-rows").innerHTML = rows.length ? rows.join("")
    : '<tr><td colspan="5" class="note">No keys yet — log in above.</td></tr>';
}

function renderSessions(sessions) {
  $("session-rows").innerHTML = sessions.length
    ? sessions.map((x) => '<tr><td class="k">' + (x.device ? "cert " + x.device : "ip " + x.client_ip) +
        "</td><td>" + x.user + "</td><td>" + x.client_ip + "</td><td>" + x.app +
        "</td><td>" + x.target + "</td><td>" + x.ttl + "s</td></tr>").join("")
    : '<tr><td colspan="6" class="note">No open sessions.</td></tr>';
}

function renderAudit(audit) {
  $("audit").innerHTML = audit.length
    ? audit.map((e) => '<div class="audit-line"><span class="meta">' +
        new Date(parseInt(e.ts || "0", 10) * 1000).toLocaleTimeString("en-GB", { hour12: false }) +
        '</span><span class="ev ' + eventClass(e.event) + '">' + e.event +
        '</span><span class="meta">' + [e.subject, e.client_ip, e.app, e.target, e.detail]
          .filter(Boolean).join(" · ") + "</span></div>").join("")
    : '<div class="note">Nothing logged yet.</div>';
}

function setGateway(open, route) {
  const gw = $("gateway");
  gw.classList.toggle("open", open);
  gw.classList.toggle("cloaked", !open);
  $("gw-icon").textContent = open ? "⇄" : "🛡";
  $("gw-state").textContent = open ? "TUNNEL OPEN" : "CLOAKED";
  $("gw-desc").textContent = open
    ? (route.device
        ? 'Only the certificate "' + route.device + '" reaches ' + route.target + " — " + route.ttl +
          "s left, re-verified every few seconds. No route exists for a source address, so another process on this host gets nothing."
        : "Connections from " + route.client_ip + " are proxied to exactly " + route.target +
          " — and nothing else — for " + route.ttl + "s more, re-verified every few seconds.")
    : "The PEP on :9000 closes any connection with no Redis record — before reading a single byte. Port scanners receive silence.";
  $("hero-status").textContent = open ? "TUNNEL OPEN" : "CLOAKED";
}

function renderJwt(tok) {
  const claims = decodeJwt(tok);
  $("jwt-empty").style.display = "none";
  $("jwt-box").style.display = "block";
  $("claims").innerHTML = Object.entries({
    sub: claims.sub, role: claims.role, client_ip: claims.client_ip,
    jti: claims.jti, exp: new Date(claims.exp * 1000).toLocaleTimeString(),
  }).map(([k, v]) => "<dt>" + esc(k) + "</dt><dd>" + esc(v) + "</dd>").join("");
  $("raw").textContent = tok;
}

// ---- login / logout ------------------------------------------------------

async function login() {
  const btn = $("btn-login");
  btn.disabled = true;
  const payload = {
    username: $("user").value,
    password: $("pw").value,
    client_ip: $("ip").value.trim(),
  };
  const app = $("app").value;
  if (app) payload.app = app;
  const device = $("device").value.trim();
  if (device) payload.device = device;
  // Posture is only sent when the toggle is on: with it off, the request
  // carries no posture claims at all, which strict mode rejects.
  if ($("posture-on").checked) payload.posture = { disk_encrypted: $("posture-value").checked };

  try {
    const res = await fetch("/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (res.status === 429 || res.status === 423) {
      const waitSecs = parseInt(res.headers.get("Retry-After") || "10", 10);
      toast((res.status === 423 ? "Account locked — " : "Rate limited — ") + "try again in " + waitSecs + "s", "err");
      log("POST /auth/login → " + res.status + " (brute-force controls)", "warn");
      setTimeout(() => { btn.disabled = false; }, waitSecs * 1000);
      return;
    }
    if (!res.ok) {
      toast("Denied: " + (body.detail || res.status), "err");
      log("POST /auth/login → " + res.status + " · " + (body.detail || ""), "err");
      btn.disabled = false;
      await refreshState();
      return;
    }

    token = body.access_token;
    const claims = decodeJwt(token);
    renderJwt(token);
    $("btn-logout").disabled = false;
    log("POST /auth/login → 200 · policy evaluated, JWT minted (jti " + claims.jti.slice(0, 8) + "…)", "ok");
    if (body.target) {
      log("EVAL login.lua → SET " + body.route_key + " = " + body.target + " EX " + body.expires_in, "ok");
      if (body.device) log('BINDING: certificate "' + body.device + '" — the source address is not an authorization key', "info");
      toast("Authorized — micro-tunnel provisioned", "ok");
    } else {
      toast("Authenticated as " + claims.role + " — no data-plane tunnel", "ok");
    }
    await refreshState();
  } catch (e) {
    toast("Control plane unreachable", "err");
    btn.disabled = false;
  }
}

async function logout() {
  const res = await fetch("/auth/logout", { method: "POST", headers: { Authorization: "Bearer " + token } });
  if (!res.ok) { toast("Logout failed", "err"); return; }
  const body = await res.json();
  log("POST /auth/logout → 200 · denylisted jti " + body.jti.slice(0, 8) + "… + route deleted", "err");
  log("PEP revalidation will close any open tunnel within one interval", "warn");
  toast("Revoked: token denylisted, tunnel torn down", "ok");
  clearSessionUI();
  await refreshState();
}

// Shared by logout and the story: forget the token and reset the login panel.
function clearSessionUI() {
  token = null;
  $("btn-login").disabled = false;
  $("btn-logout").disabled = true;
  $("jwt-box").style.display = "none";
  $("jwt-empty").style.display = "block";
}

// ---- gateway probe -------------------------------------------------------

async function probeGateway() {
  const el = $("probe");
  el.className = "probe-result";
  el.textContent = "connecting…";
  el.style.display = "block";
  try {
    const cert = $("probe-cert").value;
    const r = await (await fetch("/demo/probe", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cert ? { cert: cert } : {}),
    })).json();
    const who = r.cert ? 'certificate "' + r.cert + '" (CN ' + r.device + ")" : "no certificate";
    if (r.allowed) {
      el.className = "probe-result probe-allow";
      el.innerHTML = "ALLOW with " + who + " — " + r.detail + "<small>Real TCP connection to " + r.addr +
        " was proxied: Redis holds a route for that identity.</small>";
      log("PEP: real TCP probe with " + who + " → ALLOW", "ok");
    } else {
      el.className = "probe-result probe-deny";
      el.innerHTML = "DENY with " + who + " — " + r.detail + "<small>Real TCP connection to " + r.addr +
        ". Either the handshake was refused or the connection was closed with no payload — the gateway stays invisible.</small>";
      log("PEP: real TCP probe with " + who + " → DENY", "err");
    }
  } catch (e) {
    el.className = "probe-result probe-deny";
    el.textContent = "probe failed";
  }
  await refreshState();
}

// ---- admin console -------------------------------------------------------

async function adminLogin() {
  const res = await fetch("/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: $("admin-pw").value, client_ip: $("ip").value.trim() }),
  });
  if (!res.ok) { toast("Admin authentication failed", "err"); return; }
  adminToken = (await res.json()).access_token;
  $("btn-admin-refresh").disabled = false;
  $("btn-lockdown").disabled = false;
  $("admin-note").innerHTML = "Authenticated with an <b>admin</b>-role token — it carries no data-plane " +
    "entitlement, so it can administer sessions but can never open a tunnel.";
  log("POST /auth/login → 200 · admin console authenticated", "ok");
  await Promise.all([adminRefresh(), loadPolicy(), refreshState()]);
}

async function adminRefresh() {
  if (!adminToken) return;
  const hdr = { Authorization: "Bearer " + adminToken };
  const [sessions, apps] = await Promise.all([
    fetch("/admin/sessions", { headers: hdr }).then((r) => r.json()),
    fetch("/admin/apps", { headers: hdr }).then((r) => r.json()),
  ]);
  // Lockouts are read-only rows, so they are safe to refresh on the 4s poll
  // alongside sessions. The policy editor is NOT here: re-rendering it would
  // wipe edits the admin is halfway through typing (see loadPolicy).
  await loadLockouts();
  $("admin-rows").innerHTML = sessions.length
    ? sessions.map((s) => '<tr><td class="k">' + (s.device ? "cert " + s.device : "ip " + s.client_ip) +
        "</td><td>" + s.user + "</td><td>" + s.app + "</td><td>" + s.ttl + "s</td>" +
        '<td><button class="btn-mini" data-device="' + (s.device || "") + '" data-ip="' +
        (s.device ? "" : s.client_ip) + '">revoke</button></td></tr>').join("")
    : '<tr><td colspan="5" class="note">No live sessions right now.</td></tr>';
  $("apps-view").innerHTML = apps.map((a) => '<div class="audit-line"><span class="ev">' + a.name +
    '</span><span class="meta">' + a.target + '</span><span class="meta">' +
    (Object.keys(a.posture_rules).length ? "requires " + JSON.stringify(a.posture_rules) : "no posture rules") +
    "</span></div>").join("");
  document.querySelectorAll("#admin-rows .btn-mini").forEach((b) => {
    b.addEventListener("click", () => revokeSession(b.dataset.device, b.dataset.ip));
  });
}

async function revokeSession(device, ip) {
  // Certificate-bound sessions are revoked by their certificate identity, not
  // by an address — that is the authorization key the PEP consults.
  const payload = device ? { device: device, reason: "console action" }
                         : { client_ip: ip, reason: "console action" };
  const res = await fetch("/admin/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken },
    body: JSON.stringify(payload),
  });
  const body = await res.json();
  if (!res.ok) { toast("Revoke failed: " + (body.detail || res.status), "err"); return; }
  toast("Force-revoked " + body.revoked_user + " at " + body.client_ip, "ok");
  log("POST /admin/revoke → 200 · " + body.revoked_user + " (" + body.binding + ") denylisted + route deleted", "err");
  await Promise.all([adminRefresh(), refreshState()]);
}

// ---- policy editor -------------------------------------------------------

async function loadPolicy() {
  // Loaded on demand only (admin login, manual refresh, after a save/delete)
  // — never on the 4s poll, or re-rendering would wipe edits the admin is
  // halfway through typing.
  if (!adminToken) return;
  const res = await fetch("/admin/policy", { headers: { Authorization: "Bearer " + adminToken } });
  if (!res.ok) {
    $("policy-list").innerHTML = '<p class="note">Policy unavailable (' + res.status + ").</p>";
    return;
  }
  POLICY = (await res.json()).apps || {};
  renderPolicy();
}

function renderPolicy() {
  const names = Object.keys(POLICY);
  if (!names.length) {
    $("policy-list").innerHTML = '<p class="note">No applications in policy.</p>';
    return;
  }
  $("policy-list").innerHTML = names.map((name) => {
    const rec = POLICY[name];
    const posture = rec.posture || {};
    return '<div class="policy-app" data-app="' + esc(name) + '">' +
      "<h4>" + esc(name) + (rec.enabled ? "" : ' <span class="off">(disabled)</span>') + "</h4>" +
      '<div class="field"><label>Target (host:port)</label>' +
      '<input class="pol-target" value="' + esc(rec.target) + '"></div>' +
      '<div class="field"><label>Allowed hours</label>' +
      '<input class="pol-hours" value="' + esc(rec.allowed_hours || "") + '" placeholder="09:00-18:00, empty = always"></div>' +
      '<div class="field"><label>Session TTL (seconds)</label>' +
      '<input class="pol-ttl" type="number" min="1" value="' + esc(rec.session_ttl_seconds) + '"></div>' +
      '<div class="field"><div class="toggle"><input type="checkbox" class="pol-disk"' +
      (posture.disk_encrypted ? " checked" : "") + '><span>require disk_encrypted</span>' +
      '<input type="checkbox" class="pol-enabled"' + (rec.enabled ? " checked" : "") + '><span>enabled</span></div></div>' +
      '<div class="row"><button class="btn-primary pol-save">Save</button>' +
      '<button class="btn-ghost pol-delete">Delete</button></div></div>';
  }).join("");
  document.querySelectorAll("#policy-list .policy-app").forEach((card) => {
    card.querySelector(".pol-save").addEventListener("click", () => savePolicy(card));
    card.querySelector(".pol-delete").addEventListener("click", () => deletePolicy(card));
  });
}

async function savePolicy(card) {
  const app = card.dataset.app;
  const ttl = parseInt(card.querySelector(".pol-ttl").value, 10);
  if (!Number.isInteger(ttl) || ttl < 1) {
    toast("Session TTL must be a whole number of seconds (at least 1)", "err");
    return;
  }
  // Merge with the loaded posture instead of replacing it: the editor only
  // shows disk_encrypted, and any other posture keys must survive a save.
  // And unchecking removes the rule entirely — {disk_encrypted: false} would
  // demand an UNencrypted disk, which is the opposite of "no requirement".
  const posture = Object.assign({}, (POLICY[app] && POLICY[app].posture) || {});
  if (card.querySelector(".pol-disk").checked) posture.disk_encrypted = true;
  else delete posture.disk_encrypted;
  const res = await fetch("/admin/policy/" + encodeURIComponent(app), {
    method: "PUT",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken },
    body: JSON.stringify({
      target: card.querySelector(".pol-target").value.trim(),
      posture: posture,
      allowed_hours: card.querySelector(".pol-hours").value.trim(),
      session_ttl_seconds: ttl,
      enabled: card.querySelector(".pol-enabled").checked,
    }),
  });
  const body = await res.json();
  if (!res.ok) { toast("Save failed: " + (body.detail || res.status), "err"); return; }
  toast("Policy saved for " + app, "ok");
  await loadPolicy();
}

async function deletePolicy(card) {
  const app = card.dataset.app;
  if (!confirm('Delete the policy for "' + app + '"? Future logins for it will be denied.')) return;
  const res = await fetch("/admin/policy/" + encodeURIComponent(app), {
    method: "DELETE",
    headers: { Authorization: "Bearer " + adminToken },
  });
  const body = await res.json();
  if (!res.ok) { toast("Delete failed: " + (body.detail || res.status), "err"); return; }
  toast("Policy deleted for " + app, "ok");
  await loadPolicy();
}

// ---- lockout management --------------------------------------------------

async function loadLockouts() {
  if (!adminToken) return;
  const res = await fetch("/admin/lockouts", { headers: { Authorization: "Bearer " + adminToken } });
  if (!res.ok) {
    $("lockout-rows").innerHTML = '<tr><td colspan="4" class="note">Lockout list unavailable (' + res.status + ").</td></tr>";
    return;
  }
  const data = await res.json();
  const rows = [];
  for (const u of (data.users || [])) {
    rows.push('<tr><td>user</td><td class="k">' + esc(u.username) + "</td><td>" + u.remaining_seconds +
      's</td><td><button class="btn-mini" data-username="' + esc(u.username) + '">unlock</button></td></tr>');
  }
  // Rate-limited IPs are NOT locked out -- they are just inside a per-IP
  // rate-limit window (opened by any login attempt). Label them as such.
  for (const entry of (data.rate_limited_ips || [])) {
    rows.push('<tr><td>rate-limited ip</td><td class="k">' + esc(entry.ip) + "</td><td>" + entry.remaining_seconds +
      's</td><td><button class="btn-mini" data-ip="' + esc(entry.ip) + '">unlock</button></td></tr>');
  }
  $("lockout-rows").innerHTML = rows.length ? rows.join("")
    : '<tr><td colspan="4" class="note">No locked users or rate-limited IPs.</td></tr>';
  document.querySelectorAll("#lockout-rows .btn-mini").forEach((b) => {
    b.addEventListener("click", () => unlockEntry(b.dataset.username, b.dataset.ip));
  });
}

async function unlockEntry(username, ip) {
  // One endpoint clears either kind of lockout; the body says which.
  const payload = username ? { username: username } : { ip: ip };
  const res = await fetch("/admin/unlock", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken },
    body: JSON.stringify(payload),
  });
  const body = await res.json();
  if (!res.ok) { toast("Unlock failed: " + (body.detail || res.status), "err"); return; }
  toast("Unlocked " + (username || ip), "ok");
  await loadLockouts();
}

// ---- lockdown ------------------------------------------------------------

// One place owns the lockdown display: the banner, the toggle label and the
// note all follow the same value, refreshed on every state poll.
function setLockdownUI(on) {
  lockdownOn = on;
  $("lockdown-banner").classList.toggle("on", on);
  $("btn-lockdown").textContent = on ? "Disable lockdown" : "Enable lockdown";
  $("lockdown-note").textContent = on
    ? "Lockdown is ON — all logins are denied."
    : "Lockdown is off.";
}

async function toggleLockdown() {
  // Flipping lockdown is a serious action, so confirm first — the label, not
  // a colour, is what marks it as destructive.
  const turningOn = !lockdownOn;
  if (turningOn && !confirm("Enable lockdown? All logins will be denied until you turn it off again.")) return;
  const res = await fetch("/admin/lockdown", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken },
    body: JSON.stringify({ on: turningOn }),
  });
  const body = await res.json();
  if (!res.ok) { toast("Lockdown failed: " + (body.detail || res.status), "err"); return; }
  setLockdownUI(body.lockdown === true);
  toast(turningOn ? "Lockdown enabled — all logins denied" : "Lockdown disabled", "ok");
  await refreshState();
}

// ==========================================================================
// ZTNA flow visualization
//
// Every animation is driven by a real response from /demo/attempt, /demo/probe
// or /auth/logout: the frames show where the system actually stopped, not a
// scripted ideal of where it should have.
// ==========================================================================

// Centre of each diagram node (viewBox coordinates) — where the stop mark goes.
const FZ_CENTER = {
  "n-client": [85, 250], "n-pdp": [330, 70], "n-redis": [660, 70],
  "n-pep": [660, 250], "n-app": [885, 250],
};

function flowLog(msg, cls) {
  // Oldest first here: the frame log reads as a story, top to bottom.
  const box = $("flowlog");
  if (box.querySelector(".note")) box.innerHTML = "";
  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = "<time>" + new Date().toLocaleTimeString("en-GB", { hour12: false }) +
    '</time><span class="' + (cls || "info") + '">' + esc(msg) + "</span>";
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

function fzNode(id, state) {
  const node = $(id);
  node.classList.remove("ok", "bad");
  if (state) node.classList.add(state);
}

function fzSeg(id, state) {
  const path = $(id);
  path.classList.remove("live", "dead");
  if (state) path.classList.add(state);
}

function fzStop(nodeId, on) {
  const mark = $("fz-stop");
  const at = FZ_CENTER[nodeId];
  if (!at) return;
  mark.setAttribute("transform", "translate(" + at[0] + "," + at[1] + ")");
  mark.setAttribute("opacity", on ? "1" : "0");
}

function resetFlow() {
  Object.keys(FZ_CENTER).forEach((id) => fzNode(id, ""));
  ["p-login", "p-provision", "p-connect", "p-lookup", "p-tunnel"].forEach((id) => {
    fzSeg(id, "");
    const label = document.getElementById("l" + id.slice(1));
    if (label) label.classList.remove("hot");
  });
  fzStop("n-pdp", false);
  $("fz-dot").setAttribute("opacity", "0");
  $("flowlog").innerHTML = "";
}

function setFlowButtons(playing) {
  ["btn-attempt", "btn-story", "btn-probe"].forEach((id) => {
    const b = $(id);
    if (b) b.disabled = playing;
  });
}

// Move the dot along one path, lighting the segment as it goes. The dot's
// position comes from the path's real geometry (getPointAtLength), so the
// animation always matches the drawn diagram.
async function fzMove(pathId, tone, ms) {
  const path = $(pathId);
  const label = document.getElementById("l" + pathId.slice(1));
  const dot = $("fz-dot");
  const len = path.getTotalLength();
  fzSeg(pathId, tone === "bad" ? "dead" : "live");
  if (label) label.classList.add("hot");
  dot.setAttribute("opacity", "1");
  const t0 = performance.now();
  const duration = ms || 520;
  await new Promise((resolve) => {
    function step(now) {
      const t = Math.min(1, (now - t0) / duration);
      const pt = path.getPointAtLength(len * t);
      dot.setAttribute("cx", pt.x);
      dot.setAttribute("cy", pt.y);
      if (t < 1) requestAnimationFrame(step); else resolve();
    }
    requestAnimationFrame(step);
  });
  dot.setAttribute("opacity", "0");
}

function renderVerdict(a) {
  $("attempt-verdict").style.display = "flex";
  const allow = a.decision === "ALLOW";
  $("vb").textContent = allow ? "ALLOW" : "DENY";
  $("vb").className = "verdict-badge " + (allow ? "allow" : "deny");
  $("vb-by").textContent = a.decided_by ? "stopped at: " + a.decided_by : "all gates passed";
  $("vb-by").className = "verdict-chip " + (a.decided_by ? "bad" : "ok");
  const wire = {
    ok: ["wire: bytes flowed", "ok"],
    denied: ["wire: refused by the gateway", "bad"],
    unavailable: ["wire: gateway unreachable", "bad"],
    "": ["wire: not consulted", ""],
  }[a.wire] || ["", ""];
  $("vb-wire").textContent = wire[0];
  $("vb-wire").className = "verdict-chip " + wire[1];
  $("vb-reason").textContent = a.reason || "";
  const cmp = $("cmp");
  if (a.requested_app || a.route_target) {
    cmp.style.display = "flex";
    $("cmp-want").textContent = "asked for: " + a.requested_app +
      (a.requested_target ? " → " + a.requested_target : "");
    $("cmp-have").textContent = a.route_target
      ? "your record delivers: " + a.route_target +
        (a.entitled_apps && a.entitled_apps.length ? " (entitled: " + a.entitled_apps.join(", ") + ")" : "")
      : "no authorization record";
  } else {
    cmp.style.display = "none";
  }
  $("attempt-trace").innerHTML = (a.stages || []).map((s) =>
    '<li class="' + (s.ok ? "ok" : "bad") + '"><span class="t-title">' + esc(s.title) +
    '</span><span class="t-detail">' + esc(s.detail) + "</span></li>").join("");
}

// Replay one attempt on the diagram, gate by gate. Each gate comes from the
// attempt's own stages, so the diagram stops exactly where the system did.
async function runTrace(a) {
  resetFlow();
  const gates = {};
  (a.stages || []).forEach((s) => { gates[s.stage] = s; });

  if (gates.identity && !gates.identity.ok) {
    fzNode("n-client", "bad");
    fzStop("n-client", true);
    flowLog("attempt rejected before any lookup: " + gates.identity.detail, "err");
    flowLog("continuous verification: the denylist is consulted on every API call", "warn");
    return;
  }

  fzNode("n-client", "ok");
  flowLog("POST /demo/attempt {app: " + a.requested_app + "} as " + a.identity, "info");
  await fzMove("p-login");
  fzNode("n-pdp", "ok");
  if (gates.identity) flowLog("identity ok: " + gates.identity.detail, "ok");

  const ent = gates.entitlement;
  if (!ent || !ent.ok) {
    fzNode("n-pdp", "bad");
    fzStop("n-pdp", true);
    flowLog("entitlement: " + ((ent && ent.detail) || a.reason), "err");
    flowLog("stopped at the policy engine — the data plane is never consulted", "err");
    fzNode("n-pep", "bad");
    if (a.route_target) {
      flowLog("this identity's live record still only delivers " + a.route_target, "warn");
      fzNode("n-redis", "ok");
    }
    return;
  }
  flowLog("entitlement: " + ent.detail, "ok");

  // The PDP reads the authorization record from Redis for this binding.
  await fzMove("p-provision");
  const route = gates.route;
  if (!route || !route.ok) {
    fzNode("n-redis", "bad");
    fzStop("n-redis", true);
    flowLog("record missing: " + ((route && route.detail) || a.reason), "err");
    fzNode("n-pep", "bad");
    flowLog("a connection now would be cloaked — closed before any byte", "err");
    return;
  }
  fzNode("n-redis", "ok");
  flowLog("record found: " + route.detail, "ok");

  const gw = gates.gateway;
  if (!gw) return;

  fzNode("n-client", "ok");
  await fzMove("p-connect");
  fzNode("n-pep", "ok");
  flowLog("PEP: real TCP connection" +
    (a.gateway && a.gateway.cert ? " presenting certificate " + a.gateway.cert : ""), "info");

  await fzMove("p-lookup");
  if (!gw.ok) {
    fzNode("n-redis", "bad");
    fzNode("n-pep", "bad");
    fzStop("n-pep", true);
    flowLog("gateway: " + gw.detail, "err");
    return;
  }
  fzNode("n-redis", "ok");
  await fzMove("p-tunnel");
  fzNode("n-app", "ok");
  if (a.delivered_app) {
    $("app-node-label").textContent = a.delivered_app +
      (a.delivered_port ? " :" + a.delivered_port : "");
  }
  flowLog("tunnel: " + gw.detail, "ok");
  flowLog("ALLOW — the request reached " + (a.delivered_app || "the protected application"), "ok");
}

function pickSurpriseApp() {
  // Default the panel to an application the selected identity is NOT entitled
  // to, so the first click demonstrates a cross-application denial.
  const user = $("att-user").value;
  const me = ENTITLED[user];
  const options = [...$("att-app").options].map((o) => o.value);
  if (!me || !options.length) return;
  const surprise = options.find((app) => !me.apps.includes(app));
  if (surprise) $("att-app").value = surprise;
}

function updateHint() {
  const user = $("att-user").value;
  const app = $("att-app").value;
  const me = ENTITLED[user];
  const hint = $("att-hint");
  if (!me || !app) { hint.textContent = ""; return; }
  hint.textContent = me.apps.includes(app)
    ? user + " is entitled to " + app + " — expect ALLOW, with a real socket opened in the last gate."
    : user + " is entitled to " + me.apps.join(", ") + " only — requesting " + app +
      " should stop at gate 2, before the data plane is ever consulted.";
}

async function ensureSession(user, fresh) {
  // fresh=true skips the cached token: the revocation story must START from a
  // real provisioning step, so an externally-revoked route is re-created rather
  // than silently reused.
  if (!fresh && token) {
    try {
      if (decodeJwt(token).sub === user) return token;
    } catch (e) { /* fall through to a fresh login */ }
  }
  const payload = {
    username: user,
    password: PW[user],
    client_ip: $("ip").value.trim() || "127.0.0.1",
  };
  if (DEVICE[user]) payload.device = DEVICE[user];
  const res = await fetch("/auth/login", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.status === 429) {
    throw new Error("rate limited — wait " + (res.headers.get("Retry-After") || "60") + "s (5 logins/min per identity)");
  }
  if (res.status === 423) throw new Error("account temporarily locked after repeated failures");
  if (!res.ok) throw new Error("login failed (HTTP " + res.status + ")");
  const body = await res.json();
  token = body.access_token;
  // In the revocation story this survives resetFlow (which runs first), so the
  // diagram narrates the actual identify step rather than starting mid-flight.
  flowLog("POST /auth/login → 200 · JWT minted for " + user +
    (payload.device ? " · binding device:" + payload.device : "") +
    " · route provisioned in one atomic Lua script", "info");
  renderJwt(token);
  $("btn-logout").disabled = false;
  await refreshState();
  return token;
}

async function doAttempt(tok, app) {
  const res = await fetch("/demo/attempt", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + tok },
    body: JSON.stringify({ app: app }),
  });
  if (res.status === 401) {
    // 401 here means continuous verification rejected the token (it was
    // revoked) — a story the diagram can tell, not a generic error.
    const err = new Error("token rejected by continuous verification (401)");
    err.revoked = true;
    throw err;
  }
  if (!res.ok) throw new Error("attempt failed: HTTP " + res.status);
  return res.json();
}

async function runAttempt() {
  const user = $("att-user").value;
  const app = $("att-app").value;
  $("btn-attempt").disabled = true;
  try {
    const tok = await ensureSession(user);
    const attempt = await doAttempt(tok, app);
    renderVerdict(attempt);
    await runTrace(attempt);
  } catch (e) {
    if (e.revoked) {
      // The server gave no stages for a 401, so build the one-gate trace the
      // diagram needs from what we know: identity verification failed.
      const synthetic = {
        identity: user, binding: "", requested_app: app, requested_target: "",
        entitled_apps: [], route_key: "", route_target: "", route_ttl: 0,
        decision: "DENY", decided_by: "continuous-verification",
        reason: "the token is on the denylist — a revoked signature is still valid but never accepted",
        wire: "",
        stages: [{ stage: "identity", ok: false, title: "Identity verified",
                   detail: "401 · revoked (jwt:deny)" }],
      };
      renderVerdict(synthetic);
      await runTrace(synthetic);
      clearSessionUI();
      await refreshState();
    } else {
      toast(String(e.message || e), "err");
    }
  } finally {
    $("btn-attempt").disabled = false;
  }
}

// The story: open a tunnel for real, revoke it for real, then prove the same
// identity now gets nothing. Every step is a live API call.
async function runStory() {
  if (fzBusy) return;
  fzBusy = true;
  setFlowButtons(true);
  const user = $("att-user").value;
  try {
    resetFlow();
    const app = (ENTITLED[user] && ENTITLED[user].apps[0]) || $("att-app").value;
    const tok = await ensureSession(user, true);
    const attempt = await doAttempt(tok, app);
    renderVerdict(attempt);
    await runTrace(attempt);
    if (attempt.decision !== "ALLOW") {
      flowLog("no tunnel opened — nothing to revoke", "warn");
      return;
    }

    flowLog("session live: " + attempt.route_key + " = " + attempt.route_target +
      " (TTL " + attempt.route_ttl + "s)", "ok");
    await wait(700);

    // --- real revocation -------------------------------------------------
    const out = await fetch("/auth/logout", { method: "POST", headers: { Authorization: "Bearer " + tok } });
    if (out.ok) {
      const ob = await out.json();
      flowLog("POST /auth/logout → denylisted jti " + ob.jti.slice(0, 8) +
        "… + route deleted, in one atomic Lua script", "err");
    }
    clearSessionUI();
    fzNode("n-redis", "bad");
    fzStop("n-redis", true);
    await refreshState();
    await wait(500);

    // --- the same identity now gets nothing ------------------------------
    const cert = DEVICE[user] || "";
    const pr = await (await fetch("/demo/probe", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(cert ? { cert: cert } : {}),
    })).json();
    fzStop("n-redis", false);
    await fzMove("p-connect", pr.allowed ? "ok" : "bad");
    fzNode("n-pep", pr.allowed ? "ok" : "bad");
    flowLog("PEP: connection with " + (cert ? "certificate " + cert : "no certificate") +
      " → " + (pr.allowed ? "ALLOW" : "DENY"), pr.allowed ? "ok" : "err");
    await fzMove("p-lookup", pr.allowed ? "ok" : "bad");
    fzNode("n-redis", "bad");
    fzStop("n-pep", !pr.allowed);
    if (pr.allowed) {
      fzNode("n-app", "ok");
      flowLog("a route still exists for this identity: " + pr.detail, "warn");
    } else {
      flowLog("GET " + attempt.route_key + " → nil → closed before any byte (cloak)", "err");
      flowLog("continuous verification: a tunnel already open would die within 5s too", "warn");
    }
    await refreshState();
  } catch (e) {
    toast(String(e.message || e), "err");
    flowLog("error: " + String(e.message || e), "err");
  } finally {
    fzBusy = false;
    setFlowButtons(false);
  }
}

// ---- wiring --------------------------------------------------------------

// Choosing an identity fills in its password, device cert and probe cert —
// the demo is about the gateway, not about remembering credentials.
$("user").addEventListener("change", () => {
  $("pw").value = PW[$("user").value] || "";
  $("device").value = DEVICE[$("user").value] || "";
  $("probe-cert").value = DEVICE[$("user").value] || "";
});
$("posture-value").addEventListener("change", () => {
  $("posture-label").textContent = $("posture-value").checked ? "true" : "false";
});

$("btn-login").addEventListener("click", login);
$("btn-logout").addEventListener("click", logout);
$("btn-probe").addEventListener("click", probeGateway);
$("btn-admin-login").addEventListener("click", adminLogin);
// Manual refresh reloads the policy editor too — the 4s poll deliberately
// does not, so it never wipes an edit in progress (see loadPolicy).
$("btn-admin-refresh").addEventListener("click", () => { adminRefresh(); loadPolicy(); });
$("btn-lockdown").addEventListener("click", toggleLockdown);
$("att-user").addEventListener("change", () => { pickSurpriseApp(); updateHint(); });
$("att-app").addEventListener("change", updateHint);
$("btn-attempt").addEventListener("click", runAttempt);
$("btn-story").addEventListener("click", runStory);

// Live feed: dashboard state every 2s, admin sessions every 4s (only once
// the console is authenticated — adminRefresh no-ops without a token).
refreshState();
setInterval(refreshState, 2000);
setInterval(() => { if (adminToken) adminRefresh(); }, 4000);
