import logging
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.auth import require_auth
from app.config import settings
from app.database import init_db
from app.models import User
from app.routes import api as api_routes
from app.routes import ui as ui_routes
from app.routes import users as users_routes
from app.routes import alerts as alerts_routes
from app.scheduler import create_scheduler

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


app = FastAPI(title="Marvin", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response


app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(ui_routes.router)
app.include_router(api_routes.router, prefix="/api")
app.include_router(users_routes.router, prefix="/api")
app.include_router(alerts_routes.router, prefix="/api")


@app.get("/openapi.json", include_in_schema=False)
async def openapi_schema(_: Annotated[User, Depends(require_auth)]):
    return JSONResponse(app.openapi())


@app.get("/docs", include_in_schema=False, response_class=HTMLResponse)
async def swagger_ui(_: Annotated[User, Depends(require_auth)]):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Marvin API docs")


@app.get("/redoc", include_in_schema=False, response_class=HTMLResponse)
async def redoc(_: Annotated[User, Depends(require_auth)]):
    return get_redoc_html(openapi_url="/openapi.json", title="Marvin API docs")


@app.exception_handler(303)
async def redirect_handler(request: Request, exc):
    return RedirectResponse(url=exc.headers["Location"], status_code=303)
