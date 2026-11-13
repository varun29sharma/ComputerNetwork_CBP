#!/usr/bin/env bash
# AegisX certificate-identity demo: authorization is bound to the certificate,
# not to the source address.
#
#   1. PKI from scripts/gen_certs.sh (demo CA + PEP server cert + one client
#      certificate per identity).
#   2. The PEP runs with AEGISX_MTLS=1: every client certificate is verified and
#      the certificate's Common Name IS the authorization identity
#      (route:device:<CN>). The source address is irrelevant.
#   3. Both protected applications run, so two identities can hold two
#      independent tunnels at the same time FROM THE SAME IP and reach two
#      different apps -- the thing a single IP-keyed route can never express.
#   4. Negative control: with only alice's route present, bob's certificate from
#      that same IP is denied (it must not inherit alice's tunnel).
#   5. Connections with no certificate are rejected at the TLS handshake.
#   6. Claiming another identity's certificate at login is refused.
#   7. The certificate CN is what the audit trail records.
#
# Ports are configurable: CP_PORT / PEP_PORT / TARGET_PORT / METRICS_PORT.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CP_PORT="${CP_PORT:-8000}"
PEP_PORT="${PEP_PORT:-9000}"
TARGET_PORT="${TARGET_PORT:-8080}"
METRICS_PORT="${METRICS_PORT:-9090}"
CERTS="${CERTS_DIR:-$ROOT/certs}"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
WORK="$(mktemp -d)"

command -v java >/dev/null || { echo "java not found"; exit 1; }
[ -x "$PYTHON" ] || { echo "venv missing"; exit 1; }
[ -f data-plane/target/aegisx-ztna-proxy.jar ] || { echo "jar missing: (cd data-plane && mvn package)"; exit 1; }
[ -f "$CERTS/ca.crt" ] || ./scripts/gen_certs.sh

TARGET_PID="" METRICS_PID="" CP_PID="" PEP_PID=""
cleanup() {
  kill "$METRICS_PID" "$TARGET_PID" "$CP_PID" "$PEP_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; exit 1; }

# The demo owns these keys: start from a genuine cloak so the negative checks
# below cannot pass by accident.
redis-cli del route:127.0.0.1 route:device:alice route:device:bob \
  sess:127.0.0.1 sess:device:alice sess:device:bob >/dev/null 2>&1 || true

echo "[1/6] starting both protected apps (:$TARGET_PORT internal-api, :$METRICS_PORT metrics-dashboard)"
"$PYTHON" examples/target_service.py --port "$TARGET_PORT" --hold >"$WORK/target.log" 2>&1 &
TARGET_PID=$!
"$PYTHON" examples/target_service.py --port "$METRICS_PORT" --hold >"$WORK/metrics.log" 2>&1 &
METRICS_PID=$!

echo "[2/6] starting control plane (PDP) on :$CP_PORT"
(cd control-plane && AEGISX_PEP_PROBE_ADDR="127.0.0.1:$PEP_PORT" \
  exec "$PYTHON" -m uvicorn app.main:app --port "$CP_PORT" --log-level warning) >"$WORK/cp.log" 2>&1 &
CP_PID=$!

echo "[3/6] starting PEP on :$PEP_PORT with mTLS REQUIRED"
AEGISX_PEP_PORT="$PEP_PORT" AEGISX_MTLS=1 \
  AEGISX_MTLS_CERT="$CERTS/pep.crt" AEGISX_MTLS_KEY="$CERTS/pep.key" AEGISX_MTLS_CA="$CERTS/ca.crt" \
  java --enable-native-access=ALL-UNNAMED -jar data-plane/target/aegisx-ztna-proxy.jar >"$WORK/pep.log" 2>&1 &
PEP_PID=$!

# Fail fast if our own apps died (e.g. the port is held by an older instance):
# otherwise the demo would silently test whatever is already listening there.
for pid_name in "$TARGET_PID:target app :$TARGET_PORT" "$METRICS_PID:target app :$METRICS_PORT"; do
  pid="${pid_name%%:*}"
  kill -0 "$pid" 2>/dev/null || { cat "$WORK/target.log" "$WORK/metrics.log"; fail "${pid_name#*:} did not start (port already in use?)"; }
done

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$CP_PORT/health" >/dev/null 2>&1 && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$CP_PORT/health" >/dev/null || { cat "$WORK/cp.log"; fail "control plane did not come up"; }
for _ in $(seq 1 120); do
  "$PYTHON" -c "import socket; socket.create_connection(('127.0.0.1', $PEP_PORT), 0.5).close()" >/dev/null 2>&1 && break
  sleep 0.25
done
grep -q "mTLS: required" "$WORK/pep.log" || { cat "$WORK/pep.log"; fail "PEP did not start with mTLS required"; }
sed -n '1,3p' "$WORK/pep.log" | sed 's/^/  /'

login() { # username password client_ip [json-extra]
  "$PYTHON" - "$CP_PORT" "$@" <<'PY'
import json, sys, urllib.error, urllib.request
cp, user, pw, ip = sys.argv[1:5]
body = {"username": user, "password": pw, "client_ip": ip}
if len(sys.argv) > 5:
    body.update(json.loads(sys.argv[5]))
req = urllib.request.Request("http://127.0.0.1:%s/auth/login" % cp,
                             data=json.dumps(body).encode(),
                             headers={"Content-Type": "application/json"})
try:
    print(json.dumps(json.load(urllib.request.urlopen(req))))
except urllib.error.HTTPError as e:
    print(json.dumps({"status": e.code, "detail": e.read().decode()[:160]}))
PY
}

# Connect to the PEP over mTLS presenting `cert` ("" = no certificate) and print
# exactly what the application sent back.
connect() { # cert-name label
  "$PYTHON" - "$PEP_PORT" "$CERTS" "$1" "$2" <<'PY'
import socket, ssl, sys
port, certs, cert, label = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.load_verify_locations(certs + "/ca.crt")
ctx.check_hostname = False
if cert:
    ctx.load_cert_chain("%s/%s.crt" % (certs, cert), "%s/%s.key" % (certs, cert))
try:
    sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=6),
                           server_hostname="localhost")
    sock.settimeout(4)
    data = sock.recv(256)
    print("%s=%r" % (label, data))
except (ssl.SSLError, OSError) as e:
    print("%s=REJECTED:%s" % (label, type(e).__name__))
PY
}

echo
echo "== 4. Both identities log in asserting their registered certificate identity =="
ALICE=$(login alice alice-dev-pw 127.0.0.1 '{"device": "alice"}')
BOB=$(login bob bob-analyst-pw 127.0.0.1 '{"device": "bob"}')
case "$ALICE" in *'"access_token"'*) : ;; *) fail "alice's device-bound login failed: $ALICE" ;; esac
case "$BOB" in *'"access_token"'*) : ;; *) fail "bob's device-bound login failed: $BOB" ;; esac
echo "  alice -> binding $(echo "$ALICE" | "$PYTHON" -c 'import json,sys; d=json.load(sys.stdin); print(d["binding"], "->", d["target"])')"
echo "  bob   -> binding $(echo "$BOB" | "$PYTHON" -c 'import json,sys; d=json.load(sys.stdin); print(d["binding"], "->", d["target"])')"
echo "route:device:alice = '$(redis-cli get route:device:alice)'"
echo "route:device:bob   = '$(redis-cli get route:device:bob)'"
echo "route:127.0.0.1    = '$(redis-cli get route:127.0.0.1)'   (must be empty)"
[ -z "$(redis-cli get route:127.0.0.1)" ] \
  || fail "device-bound logins must not write a source-address route"
echo "PASS: two independent routes exist for two identities, and none for the IP"

echo
echo "== 5. Two tunnels live at once, from the SAME IP, reaching DIFFERENT apps =="
connect alice alice >"$WORK/alice.out"
connect bob bob >"$WORK/bob.out"
sed 's/^/  /' "$WORK/alice.out" "$WORK/bob.out"

grep -q "alice=b'aegisx-demo-target tunnel established on :$TARGET_PORT" "$WORK/alice.out" \
  || fail "alice did not reach internal-api: $(cat "$WORK/alice.out")"
echo "PASS: alice's certificate -> internal-api (:$TARGET_PORT)"

grep -q "bob=b'aegisx-demo-target tunnel established on :$METRICS_PORT" "$WORK/bob.out" \
  || fail "bob did not reach metrics-dashboard: $(cat "$WORK/bob.out")"
echo "PASS: bob's certificate -> metrics-dashboard (:$METRICS_PORT)"

# The decisive check: one source address, two simultaneous tunnels, two
# destinations. An IP-keyed route can only ever express one of them.
[ "$(redis-cli dbsize)" -gt 0 ] || fail "no state present"
SESSIONS=$(curl -sS -H "Authorization: Bearer $(echo "$ALICE" | "$PYTHON" -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')" \
  "http://127.0.0.1:$CP_PORT/auth/verify")
echo "  /auth/verify (alice): $SESSIONS"
BINDINGS=$(redis-cli --scan --pattern 'route:device:*' | sort | tr '\n' ' ')
echo "  concurrent device routes: $BINDINGS"
[ "$(redis-cli --scan --pattern 'route:device:*' | wc -l | tr -d ' ')" = "2" ] \
  || fail "expected exactly two concurrent device-bound routes"
echo "PASS: same IP, two live tunnels, two destinations -- IP could not express this"

echo
echo "== 6. Negative control: with only alice's route, bob's certificate is denied =="
redis-cli del route:device:bob sess:device:bob >/dev/null
connect bob bob-alone >"$WORK/bob-alone.out"
sed 's/^/  /' "$WORK/bob-alone.out"
grep -q "bob-alone=REJECTED" "$WORK/bob-alone.out" || grep -q "bob-alone=b''" "$WORK/bob-alone.out" \
  || fail "bob reached an app with no route: $(cat "$WORK/bob-alone.out")"
echo "PASS: bob's certificate from the same IP got nothing while alice's tunnel stayed open"

connect alice alice-still >"$WORK/alice-still.out"
sed 's/^/  /' "$WORK/alice-still.out"
grep -q "aegisx-demo-target" "$WORK/alice-still.out" \
  || fail "bob's denial disturbed alice's tunnel: $(cat "$WORK/alice-still.out")"
echo "PASS: alice's tunnel was unaffected -- the denial was per certificate"

echo
echo "== 7. No certificate, and an identity claiming someone else's certificate =="
connect "" no-cert >"$WORK/nocert.out"
sed 's/^/  /' "$WORK/nocert.out"
grep -q "no-cert=REJECTED" "$WORK/nocert.out" || fail "a client with no certificate was not rejected"
echo "PASS: no client certificate -> rejected at the handshake"

SPOOF=$(login alice alice-dev-pw 203.0.113.77 '{"device": "bob"}')
case "$SPOOF" in *'"status": 403'*) echo "PASS: alice asserting device 'bob' -> 403" ;;
  *) fail "alice was allowed to assert bob's certificate identity: $SPOOF" ;; esac

echo
echo "== 8. The certificate identity is what the audit trail records =="
redis-cli xrevrange audit:events + - COUNT 40 2>/dev/null | grep -A1 "^device" | head -8 | sed 's/^/  /'
redis-cli xrevrange audit:events + - COUNT 40 2>/dev/null | grep -A1 "^device" | grep -q alice \
  || fail "certificate CN was not audited as the device identity"
echo "PASS: audit records device=alice for the allowed tunnel"
redis-cli xrevrange audit:events + - COUNT 40 2>/dev/null | grep -A1 "^detail" | grep -q "no-device-route" \
  || fail "the denial for bob's certificate was not audited as no-device-route"
echo "PASS: audit records the reason for the denied certificate (no-device-route)"

echo
echo "== 9. The dashboard probe can present a certificate too =="
for who in alice bob; do
  RESP=$(curl -sS -X POST "http://127.0.0.1:$CP_PORT/demo/probe" \
    -H 'Content-Type: application/json' -d "{\"cert\": \"$who\"}")
  echo "  probe cert=$who -> $RESP"
  case "$who:$RESP" in
    alice:*'"allowed":true'*) : ;;
    bob:*'"allowed":false'*) : ;;
    *) fail "unexpected probe verdict for $who" ;;
  esac
done
echo "PASS: probe with alice's certificate is allowed; with bob's it is denied"

echo
echo "ALL MTLS CHECKS PASSED"
