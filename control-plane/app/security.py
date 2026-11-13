"""JWT minting / verification (HS256) with a jti claim for revocation."""
import time
import uuid
from typing import Dict

import jwt

from . import config


def mint_token(
    subject: str,
    role: str,
    client_ip: str,
    device: str = "",
    binding: str = "",
) -> str:
    """Issue a stateless access token describing the authorization binding.

    The jti claim is what makes revocation possible: the denylist keys
    (jwt:deny:<jti>) are derived from it, and its lifetime is pinned to the
    token's remaining exp so Redis prunes entries on its own.

    `binding` is the identity the data-plane authorization is keyed on
    ("device:<CN>" for certificate-bound sessions, otherwise the source
    address), so a logout tears down exactly the route that was created -- not
    whatever address the request happens to come from.
    """
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "client_ip": client_ip,
        "jti": uuid.uuid4().hex,
        "iat": now,
        "exp": now + config.ACCESS_TOKEN_TTL_SECONDS,
    }
    if binding:
        payload["binding"] = binding
    if device:
        payload["device"] = device
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> Dict[str, object]:
    """Decode + verify signature/expiry. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
