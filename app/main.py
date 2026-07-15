import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
from app.deps import WebUser
from app.fetchers.transport import RetryTransport
from app.logging_config import setup_logging
from app.middleware import CSRFOriginMiddleware
from app.routes import alerts as alerts_routes
from app.routes import api as api_routes
from app.routes import keys as keys_routes
from app.routes import ui as ui_routes
from app.routes import users as users_routes
from app.scheduler import create_scheduler
from app.version import get_version

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    from app.auth import seed_admin

    await seed_admin()

    # Bound the outbound connection pool and wrap the transport so transient store
    # failures are retried with backoff instead of permanently failing a refresh (#108).
    # Limits live on the inner transport: httpx ignores AsyncClient(limits=...) when a
    # custom transport is supplied. follow_redirects stays True for store scraping;
    # webhook delivery overrides it to False per-request in app/webhooks.py.
    limits = httpx.Limits(
        max_connections=settings.httpx_max_connections,
        max_keepalive_connections=settings.httpx_max_keepalive_connections,
    )
    transport = RetryTransport(
        httpx.AsyncHTTPTransport(limits=limits),
        max_retries=settings.httpx_max_retries,
        backoff_base=settings.httpx_backoff_base,
        backoff_cap=settings.httpx_backoff_cap,
    )
    client = httpx.AsyncClient(
        timeout=settings.httpx_timeout,
        headers={"User-Agent": "Mozilla/5.0 (compatible; IcebergEBS/1.0)"},
        follow_redirects=True,
        transport=transport,
    )
    app.state.http_client = client

    scheduler = create_scheduler(client)
    scheduler.start()
    app.state.scheduler = scheduler

    yield

    scheduler.shutdown(wait=False)
    await client.aclose()


app = FastAPI(
    title="IcebergEBS", version=get_version(), lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
)

# CSRF defence-in-depth (#107): reject cookie-authenticated, state-changing requests
# whose Origin/Referer doesn't match the request host (or a trusted origin). Bearer
# M2M requests carry no session cookie and are unaffected.
app.add_middleware(
    CSRFOriginMiddleware,
    trusted_origins=[o.strip() for o in settings.trusted_origins.split(",") if o.strip()],
)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    """Liveness probe: the process is up and serving. No dependency checks — a
    failing dependency must not cause the orchestrator to kill an otherwise-live
    pod (that's what /readyz is for)."""
    return JSONResponse({"status": "ok"})


@app.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness probe: verify the database is reachable before taking traffic.

    Also reports the fleet's last successful watchlist refresh (#89) so an external
    monitor can catch "the app is up but the scheduler hasn't refreshed in a day" —
    invisible to /healthz and to a bare 200 here. It's advisory only: a stale refresh
    does NOT flip readiness (the app still serves), it just enriches the JSON body.
    """
    from sqlalchemy import text

    from app.database import engine

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            # Raw SQL (not the ORM) keeps this type-clean and dependency-free; `success`
            # is a boolean column so `WHERE success` selects the successful refreshes.
            last_success = (await conn.execute(text("SELECT max(fetched_at) FROM fetchlog WHERE success"))).scalar()
    except Exception:
        logging.getLogger(__name__).exception("Readiness check failed: database unreachable")
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    return JSONResponse(
        {
            "status": "ok",
            "database": "up",
            "last_successful_refresh": last_success.isoformat() if last_success else None,
        }
    )


# Conservative app-layer security-header floor (#66, defence-in-depth). In production
# the reverse proxy (nginx/security_headers.conf) is the source of truth: it strips
# these upstream copies and re-adds its own canonical CSP + HSTS, so exactly one value
# reaches the client. This floor only matters on a non-proxied path (or if the proxy
# header config regresses). script-src/default-src are deliberately omitted so that on
# any path where both the app and proxy CSPs are enforced, the app policy can never
# intersect with — and break — the proxy's CDN asset loading.
_BASELINE_CSP = "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers.setdefault("Content-Security-Policy", _BASELINE_CSP)
    # HSTS only when the deployment is HTTPS (secure_cookies is the prod signal).
    # Sending it over plain-HTTP dev is meaningless and could poison a later
    # localhost HTTPS listener.
    if settings.secure_cookies:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


app.mount("/static", StaticFiles(directory="static"), name="static")

# Each /api router declares its own prefix + tags (see app/routes/*.py).
app.include_router(ui_routes.router)
app.include_router(api_routes.router)
app.include_router(users_routes.router)
app.include_router(alerts_routes.router)
app.include_router(keys_routes.router)


@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema(_: WebUser):
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False, response_class=HTMLResponse)
async def swagger_ui(_: WebUser):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="IcebergEBS API docs")


@app.get("/redoc", include_in_schema=False, response_class=HTMLResponse)
async def redoc(_: WebUser):
    return get_redoc_html(openapi_url="/openapi.json", title="IcebergEBS API docs")


@app.exception_handler(303)
async def redirect_handler(request: Request, exc):
    return RedirectResponse(url=exc.headers["Location"], status_code=303)
