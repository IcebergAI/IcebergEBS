import json
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import clear_session, get_current_user, require_auth, require_admin, set_session, verify_credentials
from app.config import settings
from app.database import get_session
from app.models import AlertDestination, AlertRule, Extension, FetchLog, User

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


def _render(request: Request, template: str, ctx: dict, user: User | None = None) -> HTMLResponse:
    flash = _get_flash(request)
    ctx["flash"] = flash
    ctx["is_admin"] = user.is_admin if user else False
    ctx["username"] = user.username if user else ""
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
    session: AsyncSession = Depends(get_session),
):
    user = await verify_credentials(username, password, session)
    if user:
        response = RedirectResponse("/", status_code=303)
        set_session(response, user.username)
        return response
    return _render(request, "login.html", {"error": "Invalid credentials"})


@router.post("/logout")
async def logout(request: Request, _: Annotated[User, Depends(require_auth)]):
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
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    extensions = (await session.exec(
        select(Extension)
        .where(Extension.user_id == current_user.id)
        .order_by(Extension.risk_score.desc().nullslast())
    )).all()

    high_risk = sum(1 for e in extensions if e.risk_score is not None and e.risk_score >= 50)

    return _render(request, "dashboard.html", {
        "extensions_json": json.dumps([_ext_to_dict(e) for e in extensions]),
        "extensions_count": len(extensions),
        "high_risk_count": high_risk,
    }, user=current_user)


# ---------------------------------------------------------------------------
# Add extension
# ---------------------------------------------------------------------------

@router.get("/extensions/add", response_class=HTMLResponse)
async def add_extension_page(
    request: Request,
    current_user: Annotated[User, Depends(require_auth)],
):
    return _render(request, "add_extension.html", {}, user=current_user)


# ---------------------------------------------------------------------------
# Extension detail
# ---------------------------------------------------------------------------

@router.get("/extensions/{ext_id}", response_class=HTMLResponse)
async def extension_detail(
    ext_id: int,
    request: Request,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
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
    }, user=current_user)


# ---------------------------------------------------------------------------
# Admin — user management
# ---------------------------------------------------------------------------

@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(
    request: Request,
    current_user: Annotated[User, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    users = (await session.exec(select(User).order_by(User.created_at))).all()
    users_data = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_admin": u.is_admin,
            "created_at": u.created_at.isoformat(),
        }
        for u in users
    ]
    return _render(request, "admin_users.html", {
        "users": users_data,
        "current_user_id": current_user.id,
    }, user=current_user)


# ---------------------------------------------------------------------------
# Account — preferences (alert destinations + rules)
# ---------------------------------------------------------------------------

@router.get("/account", response_class=HTMLResponse)
async def account_page(
    request: Request,
    current_user: Annotated[User, Depends(require_auth)],
    session: Annotated[AsyncSession, Depends(get_session)],
):
    destinations = (await session.exec(
        select(AlertDestination)
        .where(AlertDestination.user_id == current_user.id)
        .order_by(AlertDestination.created_at)
    )).all()

    rules = (await session.exec(
        select(AlertRule)
        .where(AlertRule.user_id == current_user.id)
        .order_by(AlertRule.created_at)
    )).all()

    extensions = (await session.exec(
        select(Extension)
        .where(Extension.user_id == current_user.id)
        .order_by(Extension.name)
    )).all()

    dest_map = {d.id: d.label for d in destinations}
    ext_map = {e.id: (e.name or e.extension_id) for e in extensions}

    destinations_data = [
        {"id": d.id, "label": d.label, "target": d.target, "enabled": d.enabled,
         "created_at": d.created_at.isoformat()}
        for d in destinations
    ]
    rules_data = [
        {"id": r.id, "destination_id": r.destination_id, "extension_id": r.extension_id,
         "event_type": r.event_type, "enabled": r.enabled, "created_at": r.created_at.isoformat(),
         "dest_label": dest_map.get(r.destination_id, "—"),
         "ext_name": ext_map.get(r.extension_id) if r.extension_id else None}
        for r in rules
    ]
    extensions_data = [
        {"id": e.id, "name": e.name or e.extension_id, "store": e.store}
        for e in extensions
    ]

    return _render(request, "account.html", {
        "destinations_json": json.dumps(destinations_data),
        "rules_json": json.dumps(rules_data),
        "extensions_json": json.dumps(extensions_data),
    }, user=current_user)


# ---------------------------------------------------------------------------
# Account — change password
# ---------------------------------------------------------------------------

@router.get("/account/password", response_class=HTMLResponse)
async def account_password_page(
    request: Request,
    current_user: Annotated[User, Depends(require_auth)],
):
    return _render(request, "account_password.html", {}, user=current_user)


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

@router.get("/help", response_class=HTMLResponse)
async def help_page(
    request: Request,
    current_user: Annotated[User, Depends(require_auth)],
):
    return _render(request, "help.html", {}, user=current_user)
