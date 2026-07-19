import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import oidc_settings, proxy, proxy_settings
from app.config import settings
from app.database import init_db
from app.deps import WebUser
from app.fetchers.transport import build_egress_transport
from app.logging_config import setup_logging
from app.middleware import CSRFOriginMiddleware
from app.oidc import service as oidc_service
from app.ratelimit import api_limiter, login_request_limiter
from app.routes import alerts as alerts_routes
from app.routes import api as api_routes
from app.routes import keys as keys_routes
from app.routes import oidc as oidc_routes
from app.routes import oidc_settings as oidc_settings_routes
from app.routes import proxy as proxy_routes
from app.routes import ui as ui_routes
from app.routes import users as users_routes
from app.scheduler import create_scheduler, drain_inflight
from app.version import get_version

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail fast on malformed proxy env config (#216) before anything else starts.
    proxy.validate_proxy_settings(settings)

    await init_db()

    from app.auth import seed_admin

    await seed_admin()

    # Load the admin-editable proxy routing config into the in-memory snapshot
    # (#216), seeding it from the ICEBERG_EBS_PROXY_* env on first boot. A failure
    # here is FATAL by design: an unloaded snapshot routes everything direct, so
    # swallowing the error would leave an EXPLICIT deployment silently failing
    # open (all egress bypassing the mandated proxy) until a restart. Startup
    # aborting is the fail-closed choice — the orchestrator retries, and init_db()
    # above already proved the DB reachable moments ago.
    from sqlmodel.ext.asyncio.session import AsyncSession

    from app.database import engine

    async with AsyncSession(engine) as session:
        await proxy_settings.refresh_cache(session)
        # Load + validate the SSO config (#32), seeding from the ICEBERG_EBS_OIDC_*
        # env on first boot. Same fail-closed rationale as the proxy snapshot: an
        # invalid config in OIDC-only mode would leave the deployment with no
        # working login path, so abort startup instead of limping.
        await oidc_settings.refresh_cache(session)
    oidc_service.register_providers()

    # The shared retry-over-proxy-routing egress chain (#108/#216), built by the one
    # factory both this client and OIDC egress use (build_egress_transport, #231).
    # This client's direct+proxied pools cap at 2× httpx_max_connections; the OIDC
    # chain (oidc/service.py) adds its own two pools, so the process-wide cap is 4×
    # (in practice one pool is active per routing mode). follow_redirects stays True
    # for store scraping; webhook delivery overrides it to False per-request in
    # app/webhooks.py.
    transport = build_egress_transport(settings)
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

    # Alerts persisted-but-not-delivered before a prior shutdown/crash are recovered at the
    # head of each scheduler refresh cycle (recover_pending_alerts in scheduler.py), backed by
    # the durable pending-alert marker (#109). We deliberately do NOT recover here in the
    # lifespan: uvicorn does not accept connections (including /healthz) until startup finishes,
    # and recovery POSTs webhooks sequentially — a backlog behind a dead/slow destination would
    # burn one webhook timeout per pending extension before the app could bind, potentially
    # exceeding the liveness window and getting the pod killed mid-recovery (#155). Deferring to
    # the scheduler keeps startup fast and unblocked; the marker makes the deferral safe — the
    # events are re-fired on the next cycle (≤ fetch_interval_minutes later), never lost. It also
    # keeps recovery running in exactly one place, so it can't race a concurrent refresh's
    # delivery of the same events.

    yield

    # Graceful shutdown (#109): stop scheduling new cycles, then explicitly await any in-flight
    # refresh so it isn't abandoned between committing a state change and firing its alert.
    # APScheduler 3.x's shutdown(wait=True) does NOT await running asyncio jobs — it cancels
    # them — so pausing + draining ourselves is what actually lets the cycle finish. The drain
    # is bounded by settings.shutdown_drain_seconds; past that (SIGKILL at the container grace
    # period) the durable pending-alert marker is the backstop, re-fired by recover_pending_alerts
    # at the head of the next scheduler refresh cycle (≤ fetch_interval_minutes later — it runs
    # there, not at startup, per #155). Keep the container grace period above shutdown_drain_seconds.
    scheduler.pause()
    await drain_inflight(settings.shutdown_drain_seconds)
    scheduler.shutdown(wait=False)
    await client.aclose()
    await oidc_service.aclose_transport()


app = FastAPI(
    title="IcebergEBS", version=get_version(), lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
)

# OIDC handshake state (#32): a dedicated, short-lived signed cookie holding only
# the Authlib state/nonce/PKCE verifier between the redirect to the IdP and the
# callback — entirely separate from the app session cookie. same_site=lax so it
# survives the top-level redirect back from the IdP. Added FIRST so it sits
# innermost (Starlette builds add_middleware layers last-added-outermost).
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key.get_secret_value(),
    session_cookie="iceberg_ebs_oidc",
    same_site="lax",
    https_only=settings.secure_cookies,
    max_age=600,
)

# CSRF defence-in-depth (#107): reject cookie-authenticated, state-changing requests
# whose Origin/Referer doesn't match the request host (or a trusted origin). Bearer
# M2M requests carry no session cookie and are unaffected. (The OIDC callback is a
# safe-method GET and thus exempt — it is protected by state+nonce+PKCE instead.)
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

    Also reports when the background scheduler last completed a refresh cycle (#89) so an
    external monitor can catch "the app is up but the scheduler has stalled" — invisible to
    /healthz and a bare 200 here. The value is an in-process signal (no history-table scan
    on the probe path, and it reflects only the *scheduler*, so an API-triggered fetch can't
    mask a stall). It's advisory: a stale/None value does NOT flip readiness.
    """
    from sqlalchemy import text

    from app.database import engine
    from app.scheduler_state import last_scheduler_run

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        logging.getLogger(__name__).exception("Readiness check failed: database unreachable")
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    last_run = last_scheduler_run()
    return JSONResponse(
        {
            "status": "ok",
            "database": "up",
            "last_scheduler_run": last_run.isoformat() if last_run else None,
        }
    )


# Canonical security headers — the app is the SINGLE source of truth (inverting the
# old #66 design where Caddy SET the full policy over an app-side floor). Emitting the
# canonical set here means every deployment path gets the same strict policy — proxied
# (Compose/Helm Caddy), bare uvicorn, and local dev — instead of the strict CSP
# evaporating off-proxy. Caddy keeps only a minimal set-if-absent (`?`) fallback in
# caddy/headers.caddy for responses the app never generates (its own 502, the :80
# redirect); a hard edge SET must never reappear there or it clobbers these values
# (the #201 double-header bug class, inverted — tests/test_security_headers.py guards).
#
# Every asset is self-hosted (#85), so no third-party origin appears in any directive.
# script-src is a strict 'self' — no hash, no unsafe-inline, no unsafe-eval (#106):
# there are NO inline scripts anywhere (the @alpinejs/csp build, the external
# theme-boot.js bootstrap; tests/test_csp_strict.py enforces it on real responses).
# style-src-elem is 'self' (no runtime <style> injection exists) while style-src-attr
# keeps 'unsafe-inline' for the pervasive inline style= attributes — style injection
# is not a script-execution vector. The plain style-src keeps 'unsafe-inline' too as
# the pre-CSP3 fallback: browsers without -elem/-attr support would otherwise fall
# through to default-src 'self' and drop every inline style= attribute.
_CANONICAL_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; style-src-elem 'self'; style-src-attr 'unsafe-inline'; "
    "font-src 'self'; img-src 'self'; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"
)
_HSTS = "max-age=63072000; includeSubDomains; preload"
_PERMISSIONS_POLICY = (
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
)


@app.middleware("http")
async def edge_rate_limit(request: Request, call_next) -> Response:
    """Token-bucket per-IP rate limits at the app edge (#188, #196).

    The app-side replacement for the nginx ``limit_req`` zones dropped when the edge
    proxy became Caddy (which has no built-in rate_limit): the ``api`` zone over the JSON
    API (``api_rate_limit_enabled``), and the tighter ``login`` zone over ``POST /login``
    (``login_rate_limit_enabled`` — separate switch so disabling API limiting can't
    silently drop login protection). ``POST /login`` alone pays the ~100ms bcrypt cost
    even for unknown users, so an unthrottled flood is a CPU-DoS and a spray vector the
    failure-keyed LoginRateLimiter can't stop. Both default off (so the test suite isn't
    throttled) and are set on in the Compose/Helm prod env, where the cluster ingress also
    limits at the true edge. Keyed on the client IP, which uvicorn derives from the
    Caddy-set canonical X-Forwarded-For (spoof-proof per #77).
    """
    limiter = None
    path = request.url.path
    # The SSO login START (/auth/oidc/<provider>/login) joins the login zone (#32):
    # it writes handshake state and is the only thing that can trigger the outbound
    # token exchange (the callback is inert without a matching signed state cookie),
    # so throttling the start bounds the exchange. The callback is DELIBERATELY not
    # rate-limited: a 429 there would burn the IdP's single-use authorization code
    # mid-flow, breaking a legitimate sign-in (e.g. several users behind one NAT IP),
    # and it's retryable only by restarting the whole flow.
    if settings.login_rate_limit_enabled and (
        (request.method == "POST" and path == "/login") or (path.startswith("/auth/oidc/") and path.endswith("/login"))
    ):
        limiter = login_request_limiter
    elif settings.api_rate_limit_enabled and path.startswith("/api/"):
        limiter = api_limiter
    if limiter is not None:
        client_ip = request.client.host if request.client else "-"
        retry_after = limiter.check(client_ip)
        if retry_after is not None:
            return JSONResponse(
                {"detail": "Rate limit exceeded. Slow down."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
    return await call_next(request)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    # Hard-set (not setdefault): the app is the canonical owner, so nothing inner may
    # shadow these values. Registered last → outermost, so every response gets them:
    # CSRF 403s, rate-limit 429s, exception handlers, and StaticFiles.
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = _CANONICAL_CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY
    # HSTS only when the deployment is HTTPS (secure_cookies is the prod signal).
    # Sending it over plain-HTTP dev is meaningless and could poison a later
    # localhost HTTPS listener.
    if settings.secure_cookies:
        response.headers["Strict-Transport-Security"] = _HSTS
    return response


app.mount("/static", StaticFiles(directory="static"), name="static")

# Each /api router declares its own prefix + tags (see app/routes/*.py).
app.include_router(ui_routes.router)
app.include_router(api_routes.router)
app.include_router(users_routes.router)
app.include_router(alerts_routes.router)
app.include_router(keys_routes.router)
app.include_router(proxy_routes.router)
app.include_router(oidc_routes.router)
app.include_router(oidc_settings_routes.router)


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
