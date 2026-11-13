"""Shared auth dependencies: every protected route re-verifies the token.

Continuous verification means a token is checked on *every* request, not just
at login -- so a logout or admin revocation takes effect immediately, even
though the token itself is stateless and cryptographically valid until exp.
"""
from typing import Optional

import jwt as pyjwt
from fastapi import Depends, Header, HTTPException, Request, status

from . import security, state


async def current_identity(
    request: Request, authorization: Optional[str] = Header(default=None)
) -> dict:
    # Reject anything that is not a well-formed Bearer token, then check the
    # signature/expiry AND the denylist: a revoked token must fail even
    # though it is still cryptographically valid.
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    try:
        claims = security.decode_token(authorization.split(" ", 1)[1].strip())
    except pyjwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    if await state.is_denied(request.app.state.redis, claims["jti"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token revoked")
    return claims


async def require_admin(claims: dict = Depends(current_identity)) -> dict:
    # Admin-only routes: a valid token is not enough, the role claim must say
    # admin -- a developer token must never list sessions or force-revoke.
    if claims.get("role") != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin role required")
    return claims
