import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import init_db
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


app = FastAPI(title="Marvin", lifespan=lifespan, docs_url=None, redoc_url=None)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(ui_routes.router)
app.include_router(api_routes.router, prefix="/api")
app.include_router(users_routes.router, prefix="/api")
app.include_router(alerts_routes.router, prefix="/api")


@app.exception_handler(303)
async def redirect_handler(request: Request, exc):
    return RedirectResponse(url=exc.headers["Location"], status_code=303)
