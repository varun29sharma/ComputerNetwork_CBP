#!/usr/bin/env bash
# AegisX local PKI for PEP mTLS: cryptographic device identity instead of a
# spoofable source IP.
#
#   certs/ca.crt, certs/ca.key          -- demo certificate authority
#   certs/pep.crt, certs/pep.key        -- PEP server certificate
#   certs/alice.crt, certs/alice.key    -- per-identity client certificates
#   certs/bob.crt, certs/bob.key
#
# The PEP requires a client certificate signed by certs/ca.crt when started
# with AEGISX_MTLS=1, which is what closes the "any local process can ride your
# route" hole documented in the README. Certs are throwaway demo material:
# regenerate them with `./scripts/gen_certs.sh --force` and never ship ca.key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${CERTS_DIR:-$ROOT/certs}"
DAYS="${CERT_DAYS:-825}"

if [ -d "$OUT" ] && [ "${1:-}" != "--force" ]; then
  echo "certs already exist in $OUT (use --force to regenerate)"
  exit 0
fi
command -v openssl >/dev/null || { echo "openssl not found"; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"
cd "$OUT"

echo "[1/4] certificate authority"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days "$DAYS" \
  -subj "/CN=AegisX Demo CA/O=AegisX" >/dev/null 2>&1

gen_leaf() {
  local name="$1"
  openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" \
    -subj "/CN=$name/O=AegisX" >/dev/null 2>&1
  if [ "$name" = "pep" ]; then
    cat > "$name.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF
  else
    cat > "$name.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
  fi
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$name.crt" -days "$DAYS" -extfile "$name.ext" >/dev/null 2>&1
  rm -f "$name.csr" "$name.ext"
}

echo "[2/4] PEP server certificate (SAN: localhost, 127.0.0.1)"
gen_leaf pep
echo "[3/4] client certificates"
gen_leaf alice
gen_leaf bob
echo "[4/4] verifying the chain"
openssl verify -CAfile ca.crt pep.crt alice.crt bob.crt
chmod 600 ./*.key

echo
echo "PKI written to $OUT"
echo "  start the PEP with:  AEGISX_MTLS=1 AEGISX_MTLS_CERT=$OUT/pep.crt \\"
echo "                       AEGISX_MTLS_KEY=$OUT/pep.key AEGISX_MTLS_CA=$OUT/ca.crt \\"
echo "                       java -jar data-plane/target/aegisx-ztna-proxy.jar"
echo "  connect as alice:    openssl s_client -quiet -connect 127.0.0.1:9000 \\"
echo "                       -cert $OUT/alice.crt -key $OUT/alice.key -CAfile $OUT/ca.crt"
