#!/usr/bin/env bash
# Enroll a device with the AegisX gateway: mint a client certificate for it
# (signed by the demo CA) and register its Common Name to a user, so that
# user may log in asserting this device -- and only this device.
#
# Usage:
#   ./scripts/enroll_device.sh <CN> <username>
#
#   CN        certificate Common Name, e.g. alice-laptop (letters, digits,
#             '.', '_' and '-', max 64 chars)
#   username  existing directory user the device belongs to, e.g. alice
#
# Environment:
#   CERTS_DIR            certs directory (default: <repo>/certs)
#   CERT_DAYS            certificate lifetime in days (default: 825)
#   AEGISX_PDP_URL       control-plane base URL (default: http://127.0.0.1:8000)
#   AEGISX_ADMIN_USER    admin username (default: admin)
#   AEGISX_ADMIN_PASSWORD admin password (default: admin-console-pw)
#
# The PDP must be running (./scripts/run_all.sh) and the demo CA must exist
# (./scripts/gen_certs.sh) before this script runs.
set -euo pipefail

usage() {
  echo "usage: $0 <CN> <username>" >&2
  echo "  example: $0 alice-laptop alice" >&2
  exit 2
}

[ $# -eq 2 ] || usage
CN="$1"
USER="$2"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${CERTS_DIR:-$ROOT/certs}"
DAYS="${CERT_DAYS:-825}"
PDP_URL="${AEGISX_PDP_URL:-http://127.0.0.1:8000}"
ADMIN_USER="${AEGISX_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${AEGISX_ADMIN_PASSWORD:-admin-console-pw}"
PYTHON="${PYTHON:-python3}"

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
[ -f "$OUT/ca.crt" ] && [ -f "$OUT/ca.key" ] || {
  echo "demo CA not found in $OUT -- run ./scripts/gen_certs.sh first" >&2
  exit 1
}
# Same alphabet the PDP validates device names with: reject anything else
# before openssl ever sees it, so a bad CN fails fast and loudly.
case "$CN" in
  *[!A-Za-z0-9._-]* | "") echo "invalid CN: use letters, digits, '.', '_' and '-'" >&2; exit 2 ;;
esac
[ -e "$OUT/$CN.crt" ] && {
  echo "certificate $CN already exists in $OUT (delete it first to re-enroll)" >&2
  exit 1
}

# --- 1. mint the client certificate (same steps as gen_certs.sh) -----------
cd "$OUT"
openssl req -newkey rsa:2048 -nodes -keyout "$CN.key" -out "$CN.csr" \
  -subj "/CN=$CN/O=AegisX" >/dev/null 2>&1
cat > "$CN.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -in "$CN.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out "$CN.crt" -days "$DAYS" -extfile "$CN.ext" >/dev/null 2>&1
rm -f "$CN.csr" "$CN.ext"
chmod 600 "$CN.key"
openssl verify -CAfile ca.crt "$CN.crt" >/dev/null
echo "certificate written: $OUT/$CN.crt (+ $CN.key)"

# --- 2. register the CN to the user via the admin API -----------------------
LOGIN=$(curl -sS -X POST "$PDP_URL/auth/login" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASSWORD\"}") || {
  echo "admin login failed: is the PDP running at $PDP_URL?" >&2; exit 1
}
TOKEN=$("$PYTHON" -c "import json,sys; print(json.loads(sys.argv[1])['access_token'])" "$LOGIN") || {
  echo "admin login failed: $LOGIN" >&2; exit 1
}
RESP=$(curl -sS -X POST "$PDP_URL/admin/devices" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER\",\"device\":\"$CN\"}") || {
  echo "device registration failed" >&2; exit 1
}
echo "registered: $RESP"
echo "device '$CN' is now enrolled for user '$USER'"
