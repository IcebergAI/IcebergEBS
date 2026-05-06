import json
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import clear_session, get_current_user, require_auth, set_session, verify_credentials
from app.config import settings
from app.database import get_session
from app.models import Extension, FetchLog

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

_FLASH_COOKIE = "marvin_flash"


def _get_flash(request: Request) -> str | None:
    raw = request.cookies.get(_FLASH_COOKIE)
    if not raw:
        return None
    try:
        s = URLSafeTimedSerializer(settings.secret_key)
        return s.loads(raw, max_age=10)
    except (BadSignature, Exception):
        return None


def _set_flash(response, message: str) -> None:
    s = URLSafeTimedSerializer(settings.secret_key)
    response.set_cookie(
        key=_FLASH_COOKIE,
        value=s.dumps(message),
        max_age=10,
        httponly=True,
        samesite="lax",
    )


def _clear_flash(response) -> None:
    response.delete_cookie(_FLASH_COOKIE)


def _render(request: Request, template: str, ctx: dict) -> HTMLResponse:
    flash = _get_flash(request)
    ctx["flash"] = flash
    response = templates.TemplateResponse(request=request, name=template, context=ctx)
    if flash:
        _clear_flash(response)
    return response


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if get_current_user(request):
        return RedirectResponse("/", status_code=303)
    return _render(request, "login.html", {"error": None})


@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if verify_credentials(username, password):
        response = RedirectResponse("/", status_code=303)
        set_session(response, username)
        return response
    return _render(request, "login.html", {"error": "Invalid credentials"})


@router.post("/logout")
async def logout(request: Request, _: Annotated[str, Depends(require_auth)]):
    response = RedirectResponse("/login", status_code=303)
    clear_session(response)
    return response


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def _ext_to_dict(e: Extension) -> dict:
    return {
        "id": e.id,
        "store": e.store,
        "extension_id": e.extension_id,
        "name": e.name,
        "publisher": e.publisher,
        "version": e.version,
        "install_count": e.install_count,
        "last_updated": e.last_updated.isoformat() if e.last_updated else None,
        "risk_score": e.risk_score,
        "watchlist": e.watchlist,
    }


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    extensions = (await session.exec(
        select(Extension).order_by(Extension.risk_score.desc().nullslast())
    )).all()

    high_risk = sum(1 for e in extensions if e.risk_score is not None and e.risk_score >= 50)

    return _render(request, "dashboard.html", {
        "extensions_json": json.dumps([_ext_to_dict(e) for e in extensions]),
        "extensions_count": len(extensions),
        "high_risk_count": high_risk,
    })


# ---------------------------------------------------------------------------
# Add extension
# ---------------------------------------------------------------------------

@router.get("/extensions/add", response_class=HTMLResponse)
async def add_extension_page(
    request: Request,
    _: Annotated[str, Depends(require_auth)],
):
    return _render(request, "add_extension.html", {})


# ---------------------------------------------------------------------------
# Extension detail
# ---------------------------------------------------------------------------

@router.get("/extensions/{ext_id}", response_class=HTMLResponse)
async def extension_detail(
    ext_id: int,
    request: Request,
    _: Annotated[str, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext:
        response = RedirectResponse("/", status_code=303)
        _set_flash(response, "Extension not found")
        return response

    fetch_logs = (await session.exec(
        select(FetchLog)
        .where(FetchLog.extension_id == ext_id)
        .order_by(FetchLog.fetched_at.desc())
        .limit(20)
    )).all()

    permissions = json.loads(ext.permissions or "[]")
    risk_detail = json.loads(ext.risk_detail or "null")
    package_analysis = json.loads(ext.package_analysis or "null")

    host_permissions = []
    if package_analysis:
        host_permissions = package_analysis.get("host_permissions", [])

    return _render(request, "extension_detail.html", {
        "ext": ext,
        "permissions": permissions,
        "host_permissions": host_permissions,
        "risk_detail": risk_detail,
        "package_analysis": package_analysis,
        "fetch_logs": fetch_logs,
    })


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

@router.get("/help", response_class=HTMLResponse)
async def help_page(
    request: Request,
    _: Annotated[str, Depends(require_auth)],
):
    return _render(request, "help.html", {})
