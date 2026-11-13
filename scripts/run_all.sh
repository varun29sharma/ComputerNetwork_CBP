#!/usr/bin/env bash
# AegisX one-command LOCAL demo (no Docker): starts the target app, the
# control plane (PDP) and the PEP, then prints the URLs and demo logins.
# Ctrl-C stops all three.
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
"$PYTHON" examples/target_service.py --port "$TARGET_PORT" >logs/target.log 2>&1 &
TARGET_PID=$!
(cd control-plane && AEGISX_PEP_PROBE_ADDR="127.0.0.1:$PEP_PORT" \
  exec "$PYTHON" -m uvicorn app.main:app --port "$CP_PORT" --log-level warning) >logs/cp.log 2>&1 &
CP_PID=$!
AEGISX_PEP_PORT="$PEP_PORT" \
  java --enable-native-access=ALL-UNNAMED -jar data-plane/target/aegisx-ztna-proxy.jar >logs/pep.log 2>&1 &
PEP_PID=$!

# 5. Wait until the control plane is ready (Redis up + users seeded).
for _ in $(seq 1 60); do
  "$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$CP_PORT/ready')" 2>/dev/null && break
  sleep 0.5
done
"$PYTHON" -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$CP_PORT/ready')" 2>/dev/null \
  || { echo "control plane did not become ready -- see logs/cp.log"; exit 1; }

cat <<EOF

AegisX is running (logs in logs/, Ctrl-C stops everything):
  dashboard:     http://127.0.0.1:$CP_PORT/
  control plane: http://127.0.0.1:$CP_PORT/ready   (PDP)
  gateway:       127.0.0.1:$PEP_PORT            (PEP -- try: curl -v http://127.0.0.1:$PEP_PORT/)

Demo logins (demo-only passwords, from control-plane/app/identity.py):
  alice / alice-dev-pw     -> internal-api (:$TARGET_PORT)
  bob   / bob-analyst-pw   -> metrics-dashboard (:9090, not started here)
  admin / admin-console-pw -> admin console (no tunnel)

Full scripted proof (own ports, runs alongside):
  CP_PORT=8010 PEP_PORT=9011 TARGET_PORT=8081 ./scripts/demo_e2e.sh
EOF

wait
