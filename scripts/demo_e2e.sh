#!/usr/bin/env bash
# AegisX end-to-end demo: proves the system's five core claims on a live stack.
#
#   1. Cloaking             -- an unauthenticated TCP client gets its connection
#                              closed before any payload is read (SDP "dark network").
#   2. Policy engine        -- entitlement and device-posture denials happen before
#                              any tunnel exists (no route key is created).
#   3. Micro-tunnel         -- after /auth/login the same client reaches exactly the
#                              one application its identity is entitled to.
#   4. Real probe           -- /demo/probe opens a real TCP connection to the PEP
#                              and reports what the gate decided.
#   5. Continuous verification -- a tunnel that is ALREADY OPEN (bytes flowing) is
#                              torn down when the session is revoked, not just
#                              future connections.
#
# Prerequisites (see README):
#   - Redis reachable at $AEGISX_REDIS_URL (default redis://127.0.0.1:6379)
#   - .venv created and control-plane/requirements.txt installed
#   - data-plane jar built: (cd data-plane && mvn package)
#   - ports free: use CP_PORT/PEP_PORT/TARGET_PORT to avoid a running preview
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CP_PORT="${CP_PORT:-8000}"
PEP_PORT="${PEP_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-8080}"
REVALIDATE="${AEGISX_REVALIDATE_SECONDS:-2}"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
WORK="$(mktemp -d)"

command -v java >/dev/null || { echo "java not found"; exit 1; }
[ -x "$PYTHON" ] || { echo "venv missing: python3 -m venv .venv && .venv/bin/pip install -r control-plane/requirements.txt"; exit 1; }
[ -f data-plane/target/aegisx-ztna-proxy.jar ] || { echo "jar missing: (cd data-plane && mvn package)"; exit 1; }

TARGET_PID="" CP_PID="" PEP_PID="" HOLD_PID=""
cleanup() {
  kill "$HOLD_PID" "$TARGET_PID" "$CP_PID" "$PEP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# The demo owns these keys: clear any route left behind by a previous run
# (a stale route:127.0.0.1 would make the step-1 cloak check meaningless).
redis-cli del route:127.0.0.1 sess:127.0.0.1 route:203.0.113.5 route:203.0.113.6 >/dev/null 2>&1 || true

echo "[1/8] starting protected target app on :$TARGET_PORT (connection-holding mode)"
"$PYTHON" examples/target_service.py --port "$TARGET_PORT" --hold >"$WORK/target.log" 2>&1 &
TARGET_PID=$!

echo "[2/8] starting control plane (FastAPI PDP) on :$CP_PORT"
# AEGISX_PEP_PROBE_ADDR keeps /demo/probe pointed at the PEP this script started
# (it defaults to 127.0.0.1:9000).
(cd control-plane && AEGISX_PEP_PROBE_ADDR="127.0.0.1:$PEP_PORT" \
  exec "$PYTHON" -m uvicorn app.main:app --port "$CP_PORT" --log-level warning) >"$WORK/cp.log" 2>&1 &
CP_PID=$!

echo "[3/8] starting data plane (Netty PEP) on :$PEP_PORT (revalidation ${REVALIDATE}s)"
AEGISX_PEP_PORT="$PEP_PORT" AEGISX_REVALIDATE_SECONDS="$REVALIDATE" \
  java --enable-native-access=ALL-UNNAMED -jar data-plane/target/aegisx-ztna-proxy.jar >"$WORK/pep.log" 2>&1 &
PEP_PID=$!

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CP_PORT/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$CP_PORT/health" >/dev/null || { cat "$WORK/cp.log"; fail "control plane did not come up"; }

# The JVM needs a moment before the PEP socket accepts connections.
pep_ready() {
  "$PYTHON" -c "import socket; s=socket.create_connection(('127.0.0.1', $PEP_PORT), 0.5); s.close()" >/dev/null 2>&1
}
for _ in $(seq 1 120); do
  pep_ready && break
  sleep 0.25
done
pep_ready || { cat "$WORK/pep.log"; fail "data plane (PEP) did not come up"; }

# Helper: talk to the PEP over raw TCP. Prints what came back; exits 1 on timeout.
pep_probe() {
  "$PYTHON" - "$PEP_PORT" "$1" <<'PY'
import socket, sys
port, mode = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=3)
s.settimeout(3)
try:
    data = s.recv(256) if mode == "read" else b""
    print("DATA=%r" % data)
except socket.timeout:
    print("DATA=b''  (timeout, no bytes)")
s.close()
PY
}

# Helper: hold a tunnel open, then report how long until the PEP closed it.
hold_tunnel() {
  "$PYTHON" - "$PEP_PORT" "$WORK/hold.out" <<'PY' &
import socket, sys, time
port, out = int(sys.argv[1]), sys.argv[2]
log = open(out, "w", buffering=1)
s = socket.create_connection(("127.0.0.1", port), timeout=5)
s.settimeout(20)
banner = s.recv(256)
log.write("BANNER=%r\n" % banner)
if b"aegisx-demo-target" not in banner:
    log.write("NO_BANNER\n")
    sys.exit(0)
t0 = time.time()
while True:
    try:
        chunk = s.recv(256)
    except socket.timeout:
        log.write("STILL_OPEN\n")
        break
    if not chunk:
        log.write("CLOSED_AFTER=%.1f\n" % (time.time() - t0))
        break
log.close()
PY
  HOLD_PID=$!
}

login() { # -> prints the JSON body (or {"status":...} on denial)
  "$PYTHON" - "$CP_PORT" "$@" <<'PY'
import json, sys, urllib.error, urllib.request
cp, user, pw, ip = sys.argv[1:5]
body = {"username": user, "password": pw, "client_ip": ip}
extra = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
body.update(extra)
req = urllib.request.Request("http://127.0.0.1:%s/auth/login" % cp,
                             data=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json"})
try:
    print(json.dumps(json.load(urllib.request.urlopen(req))))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "detail": e.read().decode()[:120]}))
PY
}

login_code() { # same but prints only the HTTP status code
  "$PYTHON" - "$CP_PORT" "$@" <<'PY'
import json, sys, urllib.error, urllib.request
cp, user, pw, ip = sys.argv[1:5]
extra = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
body = {"username": user, "password": pw, "client_ip": ip}
body.update(extra)
req = urllib.request.Request("http://127.0.0.1:%s/auth/login" % cp,
                             data=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json"})
try:
    urllib.request.urlopen(req)
    print(200)
except urllib.error.HTTPError as e:
    print(e.code)
PY
}

echo
echo "== 1. Cloaking: connect to the PEP without authenticating =="
OUT=$(pep_probe read)
echo "PEP said: $OUT"
case "$OUT" in
  *"DATA=b''"*) echo "PASS: connection closed with zero payload -> client sees silence" ;;
  *) fail "unauthenticated client reached the target: $OUT" ;;
esac

echo
echo "== 2. Policy engine: entitlement and posture are enforced before any tunnel =="
CODE=$(login_code alice alice-dev-pw 203.0.113.5 '{"app": "metrics-dashboard"}')
[ "$CODE" = "403" ] || fail "cross-app request should be 403, got $CODE"
echo "PASS: alice asking for bob's app -> HTTP 403 (not entitled)"
CODE=$(login_code alice alice-dev-pw 203.0.113.6 '{"posture": {"disk_encrypted": false}}')
[ "$CODE" = "403" ] || fail "failing posture should be 403, got $CODE"
echo "PASS: compromised-device posture -> HTTP 403 (disk_encrypted=false)"
[ -z "$(redis-cli get route:203.0.113.5)" ] && [ -z "$(redis-cli get route:203.0.113.6)" ] \
  || fail "a denied login left a route behind"
echo "PASS: denied logins created no route records"

echo
echo "== 3. Authenticate alice and provision the micro-tunnel =="
LOGIN=$(login alice alice-dev-pw 127.0.0.1)
echo "login response: $LOGIN"
case "$LOGIN" in *'"access_token"'*) : ;; *) fail "login failed: $LOGIN" ;; esac
TOKEN=$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['access_token'])" "$LOGIN")
echo "redis route:127.0.0.1 = $(redis-cli get route:127.0.0.1) (TTL $(redis-cli ttl route:127.0.0.1)s)"
echo "redis sess:127.0.0.1  = $(redis-cli hgetall sess:127.0.0.1 | tr '\n' ' ')"

echo
echo "== 4. Micro-tunnel: same client now reaches the protected app =="
OUT=$(pep_probe read)
echo "PEP said: $OUT"
case "$OUT" in
  *aegisx-demo-target*) echo "PASS: bytes proxied through the authorized tunnel" ;;
  *) fail "unexpected response through the PEP: $OUT" ;;
esac

echo
echo "== 5. Real probe endpoint reports what the gate decided =="
PROBE=$(curl -sS -X POST "http://127.0.0.1:$CP_PORT/demo/probe" -H 'Content-Type: application/json' -d '{}')
echo "probe response: $PROBE"
case "$PROBE" in *'"allowed":true'*) echo "PASS: real TCP probe through the PEP -> ALLOW" ;; *) fail "probe did not allow: $PROBE" ;; esac

echo
echo "== 6. Continuous verification: token and metrics while live =="
curl -sS -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$CP_PORT/auth/verify"
echo
METRICS=$(curl -sS "http://127.0.0.1:$CP_PORT/metrics")
echo "metrics: $METRICS"

echo
echo "== 7. Hold a tunnel open, then revoke the session underneath it =="
hold_tunnel
for _ in $(seq 1 30); do
  grep -q BANNER "$WORK/hold.out" 2>/dev/null && break
  sleep 0.2
done
grep -q "BANNER=b'aegisx-demo-target" "$WORK/hold.out" || { cat "$WORK/hold.out"; fail "could not open a held tunnel"; }
echo "PASS: tunnel open and carrying bytes (client is idle, waiting)"

curl -sS -X POST -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$CP_PORT/auth/logout"
echo
echo "redis route:127.0.0.1 = '$(redis-cli get route:127.0.0.1)'  (deleted)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$CP_PORT/auth/verify")
[ "$CODE" = "401" ] || fail "revoked token still verifies (HTTP $CODE)"
echo "PASS: revoked token rejected (HTTP 401)"

DEADLINE=$(( ${REVALIDATE%.*} + 8 ))
for _ in $(seq 1 $(( DEADLINE * 4 ))); do
  grep -q CLOSED_AFTER "$WORK/hold.out" 2>/dev/null && break
  sleep 0.25
done
wait "$HOLD_PID" 2>/dev/null || true
cat "$WORK/hold.out"
grep -q CLOSED_AFTER "$WORK/hold.out" \
  || fail "the open tunnel survived revocation (should close within ${REVALIDATE}s)"
echo "PASS: the ALREADY-OPEN tunnel was closed by PEP revalidation, not by a new connection"
grep -q STILL_OPEN "$WORK/hold.out" && fail "client timed out instead of seeing the close"

echo
echo "== 8. Cloaking restored: PEP refuses the same client again =="
OUT=$(pep_probe read)
echo "PEP said: $OUT"
case "$OUT" in
  *"DATA=b''"*) echo "PASS: connection silently dropped again" ;;
  *) fail "revoked client still reaches the target: $OUT" ;;
esac

echo
echo "== audit trail (Redis Stream) =="
redis-cli xrevrange audit:events + - COUNT 8 2>/dev/null | sed 's/^/  /'

echo
echo "ALL CHECKS PASSED"
