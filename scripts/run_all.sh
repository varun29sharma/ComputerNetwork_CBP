#!/usr/bin/env bash
# AegisX one-command LOCAL demo (no Docker): starts the target app, the
# control plane (PDP) and the PEP, then prints the URLs and demo logins.
# Ctrl-C stops all three.
#
#   ./scripts/run_all.sh          -- plain HTTP control plane (default)
#   ./scripts/run_all.sh --tls    -- control plane over HTTPS (AEGISX_TLS=1
#                                    does the same); needs certs/pdp.crt +
#                                    certs/pdp.key from ./scripts/gen_certs.sh
#
# Needs: Python 3.12, Java 17+, Maven, and a Redis on 127.0.0.1:6379.
# No Redis? Start one (redis-server --port 6379 --daemonize yes) or run
# `docker compose up` instead -- it brings its own Redis.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CP_PORT="${CP_PORT:-8000}"          # control plane (FastAPI PDP)
PEP_PORT="${PEP_PORT:-9000}"        # data plane (Netty PEP)
TARGET_PORT="${TARGET_PORT:-8080}"  # demo protected app (internal-api)
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"

# TLS mode for the control plane only (the PEP's mTLS is separate): the PDP
# serves HTTPS with its own certificate, so dashboard logins never cross the
# wire in cleartext even on a shared network. Default stays plain HTTP.
TLS=0
if [ "${1:-}" = "--tls" ] || [ "${AEGISX_TLS:-0}" = "1" ]; then
  TLS=1
fi
SCHEME="http"
if [ "$TLS" = "1" ]; then
  SCHEME="https"
  # Refuse early with a clear hint instead of letting uvicorn die on a
  # missing file halfway through startup.
  [ -f "$ROOT/certs/pdp.crt" ] && [ -f "$ROOT/certs/pdp.key" ] || {
    echo "TLS mode needs the PDP certificate: certs/pdp.crt + certs/pdp.key";
    echo "Generate it first: ./scripts/gen_certs.sh";
    exit 1; }
fi

command -v java >/dev/null || { echo "java not found (need Java 17+)"; exit 1; }
command -v mvn >/dev/null || { echo "mvn not found"; exit 1; }

# 1. Python env (created once, reused on later runs).
[ -x "$PYTHON" ] || python3 -m venv .venv
"$PYTHON" -m pip install -q -r control-plane/requirements.txt

# 2. Redis must already be running -- this script starts apps, not infra.
"$PYTHON" -c "import socket; socket.create_connection(('127.0.0.1', 6379), 2).close()" 2>/dev/null \
  || { echo "Redis is not reachable on 127.0.0.1:6379.";
       echo "Start one: redis-server --port 6379 --daemonize yes";
       echo "Or run the whole stack in Docker: docker compose up";
       exit 1; }

# 3. Build the PEP jar (fast after the first run -- Maven caches everything).
(cd data-plane && mvn -q package -DskipTests)

mkdir -p logs
TARGET_PID="" CP_PID="" PEP_PID=""
cleanup() {
  echo; echo "stopping target, control plane and PEP..."
  kill "$TARGET_PID" "$CP_PID" "$PEP_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# 4. Start the three processes; logs go under logs/ (git-ignored).
# In TLS mode uvicorn serves the PDP certificate; the demo CA signs it, so
# clients trust it with --cacert certs/ca.crt.
TLS_ARGS=()
if [ "$TLS" = "1" ]; then
  TLS_ARGS=(--ssl-keyfile "$ROOT/certs/pdp.key" --ssl-certfile "$ROOT/certs/pdp.crt")
fi
"$PYTHON" examples/target_service.py --port "$TARGET_PORT" >logs/target.log 2>&1 &
TARGET_PID=$!
(cd control-plane && AEGISX_PEP_PROBE_ADDR="127.0.0.1:$PEP_PORT" \
  exec "$PYTHON" -m uvicorn app.main:app --port "$CP_PORT" --log-level warning "${TLS_ARGS[@]}") >logs/cp.log 2>&1 &
CP_PID=$!
AEGISX_PEP_PORT="$PEP_PORT" \
  java --enable-native-access=ALL-UNNAMED -jar data-plane/target/aegisx-ztna-proxy.jar >logs/pep.log 2>&1 &
PEP_PID=$!

# 5. Wait until the control plane is ready (Redis up + users seeded). In TLS
# mode the probe verifies the PDP certificate against the demo CA, the same
# way a real client would.
ready_check() {
  if [ "$TLS" = "1" ]; then
    "$PYTHON" -c "import ssl, urllib.request; ctx = ssl.create_default_context(cafile='$ROOT/certs/ca.crt'); urllib.request.urlopen('https://127.0.0.1:$CP_PORT/ready', context=ctx)" 2>/dev/null
  else
    "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$CP_PORT/ready')" 2>/dev/null
  fi
}
for _ in $(seq 1 60); do
  ready_check && break
  sleep 0.5
done
ready_check \
  || { echo "control plane did not become ready -- see logs/cp.log"; exit 1; }

cat <<EOF

AegisX is running (logs in logs/, Ctrl-C stops everything):
  dashboard:     $SCHEME://127.0.0.1:$CP_PORT/
  control plane: $SCHEME://127.0.0.1:$CP_PORT/ready   (PDP)
  gateway:       127.0.0.1:$PEP_PORT            (PEP -- try: curl -v http://127.0.0.1:$PEP_PORT/)

Demo logins (demo-only passwords, from control-plane/app/identity.py):
  alice / alice-dev-pw     -> internal-api (:$TARGET_PORT)
  bob   / bob-analyst-pw   -> metrics-dashboard (:9090, not started here)
  admin / admin-console-pw -> admin console (no tunnel)

Full scripted proof (own ports, runs alongside):
  CP_PORT=8010 PEP_PORT=9011 TARGET_PORT=8081 ./scripts/demo_e2e.sh
EOF

wait
