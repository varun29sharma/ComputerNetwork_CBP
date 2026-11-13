"""AegisX Control Plane -- the Policy Decision Point (PDP) of NIST SP 800-207.

Role split inside this process:
  * Policy Engine (PE)         -- /auth/login: identity verification, entitlement
                                 check, device-posture evaluation, JWT minting.
  * Policy Administrator (PA)  -- Lua-atomic route provisioning, session records
                                 (/admin/sessions), revocation (/auth/logout,
                                 /admin/revoke).
  * Policy Information Point (PIP) -- the users:<name> directory in Redis
                                 (stand-in for an OIDC/LDAP IdP; posture claims
                                 stand in for a device-health service).

Identity binding
----------------
A session is authorized by a *binding*: the verified certificate Common Name
("device:alice") when the login asserts a device identity, otherwise the source
address. Only the binding keys routes and sessions, and a login may only assert
the device registered to it -- so a PEP running with mTLS (which authorizes the
certificate CN and nothing else) cannot be ridden by another process on the
same host.

This file only wires the app together: lifespan (connect Redis, seed the demo
directory), the routers (one module per area), and the dashboard page routes.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import identity, state
from .routes_admin import router as admin_router
from .routes_auth import router as auth_router
from .routes_demo import router as demo_router
from .routes_health import router as health_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = await state.connect()
    await identity.seed_users(app.state.redis)
    yield
    await app.state.redis.aclose()


app = FastAPI(title="AegisX Control Plane", version="0.3.0", lifespan=lifespan)

app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(demo_router)
app.include_router(health_router)

# The dashboard is three plain files (index.html + style.css + app.js); the
# page routes below serve the HTML, this mount serves the CSS and JS.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    page = STATIC_DIR / "index.html"
    if not page.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dashboard asset missing")
    return FileResponse(page, media_type="text/html")
