"""Liveness and readiness.

/health says the process is up (Redis answers a ping). /ready says the PDP can
actually serve a login: Redis is reachable AND the user directory is seeded --
without seeded users every login would 401, so the instance must not receive
traffic yet. Orchestrators poll /ready before routing to a fresh instance.
"""
from typing import Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()


@router.get("/health")
async def health(request: Request) -> Dict[str, str]:
    await request.app.state.redis.ping()
    return {"status": "ok"}


@router.get("/ready")
async def ready(request: Request):
    """200 {"status": "ready"} only when Redis pings OK and at least one
    users:<name> record exists (seed_users writes them at startup)."""
    redis = request.app.state.redis
    try:
        await redis.ping()
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": "redis unreachable"},
        )
    seeded = False
    async for _ in redis.scan_iter(match="users:*", count=10):
        seeded = True
        break
    if not seeded:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": "user directory not seeded"},
        )
    return {"status": "ready"}
