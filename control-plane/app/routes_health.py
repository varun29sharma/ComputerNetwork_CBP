"""Liveness and readiness.

/health says the process is up (Redis answers a ping). /ready says the PDP can
actually serve a login: Redis is reachable AND the user directory is seeded --
without seeded users every login would 401, so the instance must not receive
traffic yet. Orchestrators poll /ready before routing to a fresh instance.

/metrics/prometheus re-renders the same counters /metrics returns as JSON in
Prometheus text format, so a scraper can collect them with no extra tooling.
"""
import time
from typing import Dict

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import state

router = APIRouter()

# Process start time, recorded once at import: the uptime gauge measures this
# process's lifetime, so a restart resets it -- that is the point of the metric.
_PROCESS_STARTED_AT = time.time()

# Counter vs gauge matters to Prometheus: a counter only ever goes up (total
# decisions), a gauge can move either way (currently live tunnels/sessions).
_COUNTERS = (
    "pep_allow_total",
    "pep_deny_total",
    "pep_closed_total",
    "pep_revoked_total",
    "logins_ok_total",
    "logins_denied_total",
    "admin_revocations_total",
)
_GAUGES = ("pep_active_tunnels", "active_sessions")


@router.get("/metrics/prometheus", response_class=PlainTextResponse)
async def metrics_prometheus(request: Request) -> PlainTextResponse:
    """The /metrics counters in Prometheus text format (one HELP + TYPE pair
    per metric, then `name value` lines). Same source of truth as the JSON
    endpoint -- state.metrics -- so the two can never disagree."""
    counts = await state.metrics(request.app.state.redis)
    lines = []
    for name in _COUNTERS:
        lines.append("# HELP {} {}".format(name, name.replace("_", " ")))
        lines.append("# TYPE {} counter".format(name))
        lines.append("{} {}".format(name, counts[name]))
    for name in _GAUGES:
        lines.append("# HELP {} {}".format(name, name.replace("_", " ")))
        lines.append("# TYPE {} gauge".format(name))
        lines.append("{} {}".format(name, counts[name]))
    lines.append("# HELP aegisx_uptime_seconds seconds since this process started")
    lines.append("# TYPE aegisx_uptime_seconds gauge")
    lines.append("aegisx_uptime_seconds {}".format(int(time.time() - _PROCESS_STARTED_AT)))
    return PlainTextResponse("\n".join(lines) + "\n")


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
