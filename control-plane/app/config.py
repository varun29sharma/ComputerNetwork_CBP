"""Environment-driven configuration for the AegisX control plane (PDP)."""
import os
from pathlib import Path

# Shared state broker between the control plane (PDP) and the data plane (PEP).
REDIS_URL = os.getenv("AEGISX_REDIS_URL", "redis://127.0.0.1:6379")

# HS256 signing secret (>= 32 bytes per RFC 7518). MUST be overridden in any
# non-local deployment.
JWT_SECRET = os.getenv(
    "AEGISX_JWT_SECRET", "dev-only-secret-change-me-0123456789abcdef0123456789abcdef"
)
JWT_ALGORITHM = "HS256"

# JWT natural lifetime (seconds) -- the "exp" claim.
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("AEGISX_TOKEN_TTL", "3600"))

# Ephemeral micro-tunnel lifetime in Redis (route:<client_ip> key TTL).
ROUTE_TTL_SECONDS = int(os.getenv("AEGISX_ROUTE_TTL", "3600"))

# Brute-force protection.
RATE_LIMIT_MAX_ATTEMPTS = int(os.getenv("AEGISX_LOGIN_RATE_LIMIT", "5"))   # per user
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("AEGISX_LOGIN_RATE_WINDOW", "60"))
RATE_LIMIT_IP_MAX_ATTEMPTS = int(os.getenv("AEGISX_LOGIN_IP_RATE_LIMIT", "30"))  # per source IP
LOGIN_FAIL_MAX = int(os.getenv("AEGISX_LOGIN_FAIL_MAX", "5"))
LOCKOUT_SECONDS = int(os.getenv("AEGISX_LOCKOUT_SECONDS", "300"))

# Posture rules: when strict, a login that omits a required posture claim is
# denied (fail-closed). Default off so the bare demo login flow still works.
POSTURE_STRICT = os.getenv("AEGISX_POSTURE_STRICT", "0") == "1"

# Where the /demo/probe endpoint reaches the data plane (real TCP probe).
PEP_PROBE_ADDR = os.getenv("AEGISX_PEP_PROBE_ADDR", "127.0.0.1:9000")

# Local PKI produced by scripts/gen_certs.sh. When the PEP runs with mTLS it
# authorizes the certificate's Common Name, never the source address, so a
# login can bind its session to the device identity it will connect with.
ROOT_DIR = str(Path(__file__).resolve().parents[2])
CERTS_DIR = os.getenv("AEGISX_CERTS_DIR", os.path.join(ROOT_DIR, "certs"))
