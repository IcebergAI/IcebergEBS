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
from app.routes import alerts as alerts_routes
from app.routes import api as api_routes
from app.routes import keys as keys_routes
from app.routes import ui as ui_routes
from app.routes import users as users_routes
from app.scheduler import create_scheduler
from app.version import get_version

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    from app.auth import seed_admin

    await seed_admin()

    client = httpx.AsyncClient(
        timeout=settings.httpx_timeout,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Marvin/1.0)"},
        follow_redirects=True,
    )
    app.state.http_client = client

    scheduler = create_scheduler(client)
    scheduler.start()
    app.state.scheduler = scheduler

    yield

    scheduler.shutdown(wait=False)
    await client.aclose()


app = FastAPI(title="Marvin", version=get_version(), lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    """Liveness probe: the process is up and serving. No dependency checks — a
    failing dependency must not cause the orchestrator to kill an otherwise-live
    pod (that's what /readyz is for)."""
    return JSONResponse({"status": "ok"})


@app.get("/readyz", include_in_schema=False)
async def readyz() -> JSONResponse:
    """Readiness probe: verify the database is reachable before taking traffic."""
    from sqlalchemy import text

    from app.database import engine

    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        logging.getLogger(__name__).exception("Readiness check failed: database unreachable")
        return JSONResponse({"status": "unavailable", "database": "down"}, status_code=503)
    return JSONResponse({"status": "ok", "database": "up"})


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
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
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Marvin API docs")


@app.get("/redoc", include_in_schema=False, response_class=HTMLResponse)
async def redoc(_: WebUser):
    return get_redoc_html(openapi_url="/openapi.json", title="Marvin API docs")


@app.exception_handler(303)
async def redirect_handler(request: Request, exc):
    return RedirectResponse(url=exc.headers["Location"], status_code=303)
