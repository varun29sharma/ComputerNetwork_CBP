"""Request/response shapes for the control-plane API (Pydantic models).

These are the contract with clients: field limits here (max_length) are the
first line of defence against oversized input, and every response model pins
down exactly what a caller may rely on.
"""
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class PostureClaims(BaseModel):
    os: Optional[str] = Field(default=None, max_length=32)
    disk_encrypted: Optional[bool] = None
    jailbroken: Optional[bool] = None


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=256)
    # The login binds to the socket's real peer address by default; this field
    # is honoured only behind a trusted proxy (AEGISX_TRUST_PROXY=1) with no
    # X-Forwarded-For header -- e.g. tests simulating a proxy. It is never
    # trusted on its own: anyone can claim any address in JSON.
    client_ip: Optional[str] = Field(default=None, max_length=45)
    # Which entitled application to open a tunnel to (default: first entitled).
    app: Optional[str] = Field(default=None, max_length=64)
    # The certificate Common Name this session will connect with. When set, the
    # session is authorized by device identity (route:device:<CN>) and the PEP
    # requires the matching client certificate; it must be the CN registered to
    # this identity. Omit it for the plaintext, source-address-keyed demo.
    device: Optional[str] = Field(default=None, max_length=64)
    # Device-posture signals (normally reported by a device agent, not the user).
    posture: Optional[PostureClaims] = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    app: str
    target: str
    route_key: str
    posture: str = "pass"
    # `binding` is the authorization identity written to Redis: "device:<CN>"
    # when the session is certificate-bound, otherwise the source address.
    binding: str = ""
    device: str = ""


class VerifyResponse(BaseModel):
    active: bool = True
    sub: str
    role: str
    client_ip: str
    jti: str
    exp: int
    # The identity the data-plane authorization is keyed on, and the certificate
    # identity backing it ("" for source-address-bound sessions).
    binding: str = ""
    device: str = ""


class RevocationResponse(BaseModel):
    status: str = "revoked"
    jti: str


class AdminRevokeRequest(BaseModel):
    """Force-revoke a live tunnel (SOC incident response).

    Identify the session by `device` (certificate CN, preferred) or by
    `client_ip` for source-address-bound sessions.
    """

    client_ip: Optional[str] = Field(default=None, max_length=45)
    device: Optional[str] = Field(default=None, max_length=64)
    reason: Optional[str] = Field(default=None, max_length=200)


class SessionModel(BaseModel):
    client_ip: str
    user: str
    role: str
    app: str
    target: str
    ttl: int
    jti: str


class ProbeRequest(BaseModel):
    """Demo-only probe options: which address to dial, and optionally which
    client certificate to present (a name under the certs directory)."""

    addr: Optional[str] = Field(default=None, max_length=64)
    cert: Optional[str] = Field(default=None, max_length=64)


class ProbeResponse(BaseModel):
    """Outcome of a real TCP connection attempt against the PEP."""

    allowed: bool
    reachable: bool
    addr: str
    detail: str
    # Certificate actually presented (its file name) and its Common Name, when
    # the probe connected over mTLS.
    cert: str = ""
    device: str = ""
    tls: bool = False
    tls_error: bool = False
    # First bytes the answering application returned (truncated). Lets a demo
    # show *which* application actually answered, not merely that one did.
    payload: str = ""


class AttemptRequest(BaseModel):
    """Ask to reach an application, using the caller's existing session.

    Deliberately takes no password: an attempt is made with a token that is
    already authenticated and continuously verified, so this demo endpoint can
    never become a password oracle that sidesteps the login rate limits.
    """

    app: str = Field(..., max_length=64)
    # Certificate to present to the PEP; defaults to the session's own binding.
    cert: Optional[str] = Field(default=None, max_length=64)
    # Demo-only override of the gateway address (same as ProbeRequest.addr), so
    # tests can exercise "gateway unavailable" deterministically.
    addr: Optional[str] = Field(default=None, max_length=64)


class AttemptStage(BaseModel):
    """One gate the attempt passed (or stopped at), for the trace UI."""

    stage: str          # identity | entitlement | route | gateway
    ok: bool
    title: str
    detail: str


class AttemptResponse(BaseModel):
    """Full decision trace of one access attempt: where it stopped and what
    the wire would actually deliver."""

    identity: str
    role: str
    binding: str
    requested_app: str
    requested_target: str
    entitled_apps: List[str] = Field(default_factory=list)
    route_key: str
    route_target: str
    route_ttl: int = 0
    decision: str = "ALLOW"          # ALLOW | DENY (policy verdict)
    decided_by: str = ""             # "" | policy-engine | gateway
    reason: str = ""
    # Observed data-plane result, kept separate from the policy verdict so an
    # unavailable/unreachable PEP never silently becomes a "policy denial":
    #   "" (no wire check), "ok", "denied", "unavailable"
    wire: str = ""
    stages: List[AttemptStage] = Field(default_factory=list)
    gateway: Optional[ProbeResponse] = None
    delivered_port: int = 0
    delivered_app: str = ""


class AppModel(BaseModel):
    name: str
    target: str
    posture_rules: Dict[str, bool] = Field(default_factory=dict)


class PolicyRecord(BaseModel):
    """One application's policy record, as stored (JSON) in the policy:apps
    hash. allowed_hours "" means always allowed; otherwise "HH:MM-HH:MM".
    session_ttl_seconds is the route + session lifetime for this app only --
    the JWT lifetime stays the global ACCESS_TOKEN_TTL_SECONDS."""

    target: str
    posture: Dict[str, bool] = Field(default_factory=dict)
    allowed_hours: str = ""
    session_ttl_seconds: int = 3600
    enabled: bool = True


class PolicyUpdate(BaseModel):
    """PUT /admin/policy/{app} body. Every field is optional on update (only
    the fields sent change); `target` is required when creating a new app."""

    target: Optional[str] = Field(default=None, max_length=128)
    posture: Optional[Dict[str, bool]] = None
    allowed_hours: Optional[str] = Field(default=None, max_length=32)
    session_ttl_seconds: Optional[int] = None
    enabled: Optional[bool] = None


class PolicyListResponse(BaseModel):
    """GET /admin/policy: the whole live policy, keyed by application name."""

    apps: Dict[str, PolicyRecord] = Field(default_factory=dict)


class DeviceRegisterRequest(BaseModel):
    """Register a device (certificate CN) to an existing user."""

    username: str = Field(..., min_length=1, max_length=64)
    device: str = Field(..., min_length=1, max_length=64)


class DeviceRevokeRequest(BaseModel):
    """Revoke a device certificate (denies future logins, kills live sessions)."""

    device: str = Field(..., min_length=1, max_length=64)


class CreateUserRequest(BaseModel):
    """Create a directory user. `device` (certificate CN) is optional."""

    username: str = Field(..., min_length=1, max_length=64)
    # 8 chars is the floor for a demo directory; a real IdP would enforce more.
    password: str = Field(..., min_length=8, max_length=256)
    role: str = Field(..., max_length=32)
    apps: List[str] = Field(default_factory=list)
    device: Optional[str] = Field(default=None, max_length=64)


class UserResponse(BaseModel):
    """What a created user looks like -- never includes the password hash."""

    username: str
    role: str
    apps: List[str] = Field(default_factory=list)
    device: str = ""


class UnlockRequest(BaseModel):
    """Clear a lockout: give a username, an IP, or both (at least one)."""

    username: Optional[str] = Field(default=None, max_length=64)
    ip: Optional[str] = Field(default=None, max_length=45)


class LockdownRequest(BaseModel):
    """Emergency lockdown switch: true stops every login, false restores it."""

    on: bool


class ServiceAccountRequest(BaseModel):
    """Create a service account (machine identity) for one application."""

    name: str = Field(..., min_length=1, max_length=64)
    app: str = Field(..., min_length=1, max_length=64)


class ServiceAuthRequest(BaseModel):
    """Exchange a service account's API key for a JWT (no password login)."""

    name: str = Field(..., min_length=1, max_length=64)
    api_key: str = Field(..., min_length=1, max_length=256)
