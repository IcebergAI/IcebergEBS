from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import and_, func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import authenticate_session, clear_session, get_current_user, set_session, verify_credentials
from app.config import settings
from app.deps import AdminUserUI, SessionDep, WebUser
from app.extension_queries import (
    EXPOSURE_EXPR,
    RISK_BANDS,
    SORT_COLUMNS,
    ExtensionFilters,
    build_extension_query,
    count_rows,
)
from app.models import AlertDestination, AlertRule, ApiKey, Extension, FetchLog, InstallObservation, User
from app.ratelimit import login_limiter
from app.routes.alerts import get_alert_log
from app.threat_intel import build_threat_intel_indicators
from app.utils import safe_json_loads
from app.version import get_version

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

_FLASH_COOKIE = "iceberg_ebs_flash"


def _ago(dt) -> str:
    if not dt:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    mins = int((datetime.now(timezone.utc) - dt).total_seconds() // 60)
    if mins < 1:
        return "just now"
    if mins < 60:
        return f"{mins}m ago"
    hrs = mins // 60
    if hrs < 24:
        return f"{hrs}h ago"
    return f"{hrs // 24}d ago"


def _get_flash(request: Request) -> str | None:
    raw = request.cookies.get(_FLASH_COOKIE)
    if not raw:
        return None
    try:
        s = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        return s.loads(raw, max_age=10)
    except Exception:
        return None


def _set_flash(response, message: str) -> None:
    s = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    response.set_cookie(
        key=_FLASH_COOKIE,
        value=s.dumps(message),
        max_age=10,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
    )


def _clear_flash(response) -> None:
    response.delete_cookie(_FLASH_COOKIE)


def _render(request: Request, template: str, ctx: dict, user: User | None = None) -> HTMLResponse:
    flash = _get_flash(request)
    ctx["flash"] = flash
    ctx["is_admin"] = user.is_admin if user else False
    ctx["username"] = user.username if user else ""
    ctx["app_version"] = get_version()
    response = templates.TemplateResponse(request=request, name=template, context=ctx)
    if flash:
        _clear_flash(response)
    return response


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session: SessionDep):
    # DB-backed validation, matching require_auth — a signature-valid cookie whose
    # user was deleted or whose password changed on another device must NOT redirect
    # to "/" (require_auth would bounce it straight back here → infinite loop, #73).
    if await authenticate_session(request, session):
        return RedirectResponse("/", status_code=303)
    # Clear any stale-but-signed cookie so it can't keep failing require_auth.
    response = _render(request, "login.html", {"error": None})
    if get_current_user(request):
        clear_session(response)
    return response


@router.post("/login")
async def login_post(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    session: SessionDep,
):
    # App-level brute-force throttle, independent of nginx (M3 / #8).
    key = login_limiter.key(request.client.host if request.client else None, username)
    retry_after = login_limiter.retry_after(key)
    if retry_after is not None:
        response = _render(
            request,
            "login.html",
            {"error": "Too many failed attempts — please try again later."},
        )
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response

    user = await verify_credentials(username, password, session)
    if user:
        login_limiter.reset(key)
        response = RedirectResponse("/", status_code=303)
        set_session(response, user.username)
        return response
    login_limiter.record_failure(key)
    return _render(request, "login.html", {"error": "Invalid credentials"})


@router.post("/logout")
async def logout(request: Request, _: WebUser):
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


def _finding_location(finding: dict, source: str) -> str:
    file = finding.get("file")
    if file:
        line = finding.get("line")
        return f"{file}:{line}" if line is not None else str(file)
    return source


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _finding_sections(rows: list[dict], source: str) -> tuple[list[dict], str]:
    locations = _unique([row["location"] for row in rows])
    details = _unique([row["detail"] for row in rows if row["detail"]])

    if len(details) == 1:
        return (
            [
                {
                    "type": "detail",
                    "detail": details[0],
                    "locations": locations,
                }
            ],
            "locations",
        )

    if len(locations) == 1:
        return (
            [
                {
                    "type": "location",
                    "location": "" if locations[0] == source else locations[0],
                    "details": details,
                }
            ],
            "findings",
        )

    if len(details) <= len(locations):
        return (
            [
                {
                    "type": "detail",
                    "detail": detail,
                    "locations": _unique([row["location"] for row in rows if row["detail"] == detail]),
                }
                for detail in details
            ],
            "entries",
        )

    return (
        [
            {
                "type": "location",
                "location": "" if location == source else location,
                "details": _unique([row["detail"] for row in rows if row["location"] == location and row["detail"]]),
            }
            for location in locations
        ],
        "entries",
    )


def _group_detection_findings(findings: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str, str], dict] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        severity = finding.get("severity") or "low"
        source = finding.get("source") or "package"
        code = finding.get("code") or ""
        title = finding.get("title") or code or "Detection finding"
        detail = finding.get("detail") or ""
        key = (severity, source, code, title)

        group = grouped.setdefault(
            key,
            {
                "code": code,
                "severity": severity,
                "title": title,
                "source": source,
                "rows": [],
                "_seen_rows": set(),
            },
        )

        location = _finding_location(finding, source)
        row_key = (location, detail)
        if row_key in group["_seen_rows"]:
            continue
        group["_seen_rows"].add(row_key)
        group["rows"].append(
            {
                "location": location,
                "detail": detail,
            }
        )

    for group in grouped.values():
        group["sections"], group["row_label"] = _finding_sections(group["rows"], group["source"])
        del group["_seen_rows"]
    return list(grouped.values())


def _stale_after() -> timedelta:
    """A watchlist extension is "stale" once it has gone this long without a
    successful refresh — two scheduled intervals (with a 1h floor for tiny
    intervals), enough to absorb one missed cycle without false alarms."""
    return timedelta(minutes=max(settings.fetch_interval_minutes * 2, 60))


async def _latest_fetch_logs(session: AsyncSession, ext_ids: list[int]) -> dict[int, FetchLog]:
    """Map each extension id to its most recent FetchLog (one query, not N+1)."""
    if not ext_ids:
        return {}
    newest = (
        select(FetchLog.extension_id, func.max(FetchLog.fetched_at).label("mx"))
        .where(FetchLog.extension_id.in_(ext_ids))
        .group_by(FetchLog.extension_id)
    ).subquery()
    rows = (
        await session.exec(
            select(FetchLog).join(
                newest,
                and_(
                    FetchLog.extension_id == newest.c.extension_id,
                    FetchLog.fetched_at == newest.c.mx,
                ),
            )
        )
    ).all()
    # Two logs could share an exact timestamp; last one wins (arbitrary but stable).
    return {fl.extension_id: fl for fl in rows}


_DASHBOARD_PAGE_SIZE = 25


@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    current_user: WebUser,
    session: SessionDep,
    store: str | None = None,
    risk: str | None = None,
    q: str | None = None,
    sort: str = "risk_score",
    order: str = "desc",
    page: int = 1,
):
    # Tolerate junk query params from the UI (don't 422 a browser) — fall back
    # to defaults rather than rejecting.
    if store not in ("chrome", "vscode", "edge"):
        store = None
    if risk not in RISK_BANDS:
        risk = None
    if sort not in SORT_COLUMNS:
        sort = "risk_score"
    if order not in ("asc", "desc"):
        order = "desc"
    q = (q or "").strip() or None
    page = max(page, 1)

    # Lightweight fleet snapshot for the stat tiles (counts + fetch health) —
    # independent of the active filter, and cheap (no JSON columns loaded).
    snapshot = (
        await session.exec(
            select(Extension.id, Extension.risk_score, Extension.watchlist, Extension.last_fetched_at).where(
                Extension.user_id == current_user.id
            )
        )
    ).all()
    extensions_count = len(snapshot)
    high_risk = sum(1 for r in snapshot if r.risk_score is not None and r.risk_score >= 50)
    watchlist_count = sum(1 for r in snapshot if r.watchlist)
    fetched = [r.last_fetched_at for r in snapshot if r.last_fetched_at]
    last_refresh = max(fetched) if fetched else None
    next_refresh = last_refresh + timedelta(minutes=settings.fetch_interval_minutes) if last_refresh else None

    now = datetime.now(timezone.utc)
    stale_after = _stale_after()
    latest_logs = await _latest_fetch_logs(session, [r.id for r in snapshot])

    def _stale(watchlist: bool, lf) -> bool:
        if not watchlist:
            return False
        if lf is None:
            return True
        if lf.tzinfo is None:
            lf = lf.replace(tzinfo=timezone.utc)
        return (now - lf) > stale_after

    unhealthy = 0
    for r in snapshot:
        log = latest_logs.get(r.id)
        # A store-outage skip (circuit breaker, #108) is not the extension's fault, so
        # it doesn't count as "failing" — a brief store blip must not spike the tile.
        # A prolonged outage still surfaces via the staleness check below.
        failing = log is not None and not log.success and not log.store_outage
        if r.watchlist and (failing or _stale(r.watchlist, r.last_fetched_at)):
            unhealthy += 1

    # Top exposure ("blast radius", #29): risk × org footprint, highest first.
    # Column-only select like the fleet snapshot; only extensions with a known
    # footprint and score qualify (exposure is NULL otherwise).
    exposure_rows = (
        await session.exec(
            select(
                Extension.id,
                Extension.name,
                Extension.store,
                Extension.risk_score,
                Extension.install_footprint,
            )
            .where(
                Extension.user_id == current_user.id,
                Extension.install_footprint.is_not(None),
                Extension.install_footprint > 0,
                Extension.risk_score.is_not(None),
            )
            .order_by(EXPOSURE_EXPR.desc())
            .limit(5)
        )
    ).all()
    top_exposure = [
        {
            "id": r.id,
            "name": r.name,
            "store": r.store,
            "risk_score": r.risk_score,
            "install_footprint": r.install_footprint,
            "exposure": r.risk_score * r.install_footprint,
        }
        for r in exposure_rows
    ]

    # Filtered + sorted + paginated page of full rows for the table. Same filter
    # object the API endpoints use (built from coerced params rather than via the
    # 422-ing dependency) — the dashboard doesn't filter by publisher.
    filters = ExtensionFilters(store=store, risk=risk, q=q, sort=sort, order=order)
    stmt = build_extension_query(current_user.id, filters)
    filtered_total = await count_rows(session, stmt)
    total_pages = max((filtered_total + _DASHBOARD_PAGE_SIZE - 1) // _DASHBOARD_PAGE_SIZE, 1)
    page = min(page, total_pages)
    offset = (page - 1) * _DASHBOARD_PAGE_SIZE
    page_rows = (await session.exec(stmt.limit(_DASHBOARD_PAGE_SIZE).offset(offset))).all()

    ext_dicts = []
    for e in page_rows:
        log = latest_logs.get(e.id)
        d = _ext_to_dict(e)
        d["last_fetch_ok"] = log.success if log is not None else None
        d["last_fetch_error"] = log.error_message if (log is not None and not log.success) else None
        d["store_outage"] = bool(log.store_outage) if log is not None else False
        d["stale"] = _stale(e.watchlist, e.last_fetched_at)
        ext_dicts.append(d)

    showing_from = offset + 1 if filtered_total else 0
    showing_to = offset + len(ext_dicts)

    # Build relative dashboard URLs that preserve the current filter/sort/page
    # state with selective overrides (None drops a param). Used by the template's
    # filter pills, sort headers and pagination links.
    base_params = {"store": store, "risk": risk, "q": q, "sort": sort, "order": order, "page": page}

    def qs(**overrides) -> str:
        params = {**base_params, **overrides}
        # Drop empty params and defaults (sort/order defaults, page 1) to keep URLs clean.
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        if clean.get("page") == 1:
            clean.pop("page", None)
        if clean.get("sort") == "risk_score":
            clean.pop("sort", None)
        if clean.get("order") == "desc":
            clean.pop("order", None)
        return "/?" + urlencode(clean) if clean else "/"

    def export_url(fmt: str) -> str:
        # Export honours the active filters/sort (but not pagination).
        params = {"format": fmt, "store": store, "risk": risk, "q": q, "sort": sort, "order": order}
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        return "/api/extensions/export?" + urlencode(clean)

    return _render(
        request,
        "dashboard.html",
        {
            "qs": qs,
            "export_csv_url": export_url("csv"),
            "export_json_url": export_url("json"),
            "extensions": ext_dicts,
            "top_exposure": top_exposure,
            "extensions_count": extensions_count,
            "high_risk_count": high_risk,
            "watchlist_count": watchlist_count,
            "unhealthy_count": unhealthy,
            "last_refresh_label": _ago(last_refresh),
            "next_refresh_label": (
                f"next ~{next_refresh.strftime('%H:%M')} UTC" if next_refresh else "next: scheduled"
            ),
            # Filter / sort / pagination state for the controls.
            "filter_store": store,
            "filter_risk": risk,
            "search_q": q or "",
            "sort": sort,
            "order": order,
            "page": page,
            "total_pages": total_pages,
            "filtered_total": filtered_total,
            "showing_from": showing_from,
            "showing_to": showing_to,
        },
        user=current_user,
    )


# ---------------------------------------------------------------------------
# Add extension
# ---------------------------------------------------------------------------


@router.get("/extensions/add", response_class=HTMLResponse)
async def add_extension_page(
    request: Request,
    current_user: WebUser,
):
    return _render(request, "add_extension.html", {}, user=current_user)


@router.get("/extensions/bulk", response_class=HTMLResponse)
async def bulk_import_page(
    request: Request,
    current_user: WebUser,
):
    return _render(request, "bulk_import.html", {}, user=current_user)


# ---------------------------------------------------------------------------
# Extension detail
# ---------------------------------------------------------------------------


@router.get("/extensions/{ext_id}", response_class=HTMLResponse)
async def extension_detail(
    ext_id: int,
    request: Request,
    current_user: WebUser,
    session: SessionDep,
):
    ext = await session.get(Extension, ext_id)
    if not ext or ext.user_id != current_user.id:
        response = RedirectResponse("/", status_code=303)
        _set_flash(response, "Extension not found")
        return response

    fetch_logs = (
        await session.exec(
            select(FetchLog).where(FetchLog.extension_id == ext_id).order_by(FetchLog.fetched_at.desc()).limit(20)
        )
    ).all()

    # Parse defensively: a partial write or manual DB edit could leave invalid JSON,
    # which must not 500 the detail page — fall back and log instead (#61, mirroring
    # the JSON API's #17 hardening).
    permissions = safe_json_loads(ext.permissions, "[]", "permissions", ext.id)
    risk_detail = safe_json_loads(ext.risk_detail, "null", "risk_detail", ext.id)
    package_analysis = safe_json_loads(ext.package_analysis, "null", "package_analysis", ext.id)

    host_permissions = []
    if package_analysis:
        package_analysis.setdefault("external_domains", [])
        package_analysis.setdefault("external_urls", [])
        package_analysis.setdefault("network_callout_urls", [])
        package_analysis.setdefault("package_sha256", "")
        package_analysis.setdefault("archive_sha256", "")
        package_analysis.setdefault("uses_eval", False)
        package_analysis.setdefault("uses_remote_code", False)
        package_analysis.setdefault("obfuscation_score", 0)
        package_analysis.setdefault("file_count", 0)
        package_analysis.setdefault("total_size_bytes", 0)
        package_analysis.setdefault("has_minified_code", False)
        package_analysis.setdefault("manifest_version", 2)
        if not isinstance(package_analysis.get("findings"), list):
            package_analysis["findings"] = []
        package_analysis["grouped_findings"] = _group_detection_findings(package_analysis["findings"])
        host_permissions = package_analysis.get("host_permissions", [])
    threat_intel_indicators = build_threat_intel_indicators(package_analysis)
    threat_intel_primary_indicators = [
        indicator for indicator in threat_intel_indicators if indicator.get("section") != "referenced"
    ]
    threat_intel_referenced_indicators = [
        indicator for indicator in threat_intel_indicators if indicator.get("section") == "referenced"
    ]
    score_history = [
        {"d": log.fetched_at.strftime("%b %d"), "s": log.risk_score_after}
        for log in reversed(fetch_logs)
        if log.success and log.risk_score_after is not None
    ]

    # Org footprint (#29): SOAR-reported installs grouped by department. The
    # headline count reuses the cached install_footprint (distinct assets); the
    # breakdown is queried live.
    dept_rows = (
        await session.exec(
            select(
                InstallObservation.department,
                func.count(func.distinct(InstallObservation.asset_id)).label("n"),
            )
            .where(InstallObservation.extension_id == ext_id)
            .group_by(InstallObservation.department)
            .order_by(func.count(func.distinct(InstallObservation.asset_id)).desc())
        )
    ).all()
    footprint_assets = ext.install_footprint or 0
    footprint_departments = [{"department": d.department or "Unassigned", "count": d.n} for d in dept_rows]
    exposure = ext.risk_score * footprint_assets if (ext.risk_score is not None and footprint_assets) else None

    return _render(
        request,
        "extension_detail.html",
        {
            "ext": ext,
            "footprint_assets": footprint_assets,
            "footprint_departments": footprint_departments,
            "exposure": exposure,
            "permissions": permissions,
            "host_permissions": host_permissions,
            "risk_detail": risk_detail,
            "package_analysis": package_analysis,
            "threat_intel_indicators": threat_intel_indicators,
            "threat_intel_primary_indicators": threat_intel_primary_indicators,
            "threat_intel_referenced_indicators": threat_intel_referenced_indicators,
            "fetch_logs": fetch_logs,
            "score_history": score_history,
        },
        user=current_user,
    )


# ---------------------------------------------------------------------------
# Admin — user management
# ---------------------------------------------------------------------------


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(
    request: Request,
    current_user: AdminUserUI,
    session: SessionDep,
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
    return _render(
        request,
        "admin_users.html",
        {
            "users": users_data,
            "current_user_id": current_user.id,
        },
        user=current_user,
    )


# ---------------------------------------------------------------------------
# Account — preferences (alert destinations + rules)
# ---------------------------------------------------------------------------


@router.get("/account", response_class=HTMLResponse)
async def account_page(
    request: Request,
    current_user: WebUser,
    session: SessionDep,
):
    destinations = (
        await session.exec(
            select(AlertDestination)
            .where(AlertDestination.user_id == current_user.id)
            .order_by(AlertDestination.created_at)
        )
    ).all()

    rules = (
        await session.exec(select(AlertRule).where(AlertRule.user_id == current_user.id).order_by(AlertRule.created_at))
    ).all()

    extensions = (
        await session.exec(select(Extension).where(Extension.user_id == current_user.id).order_by(Extension.name))
    ).all()

    dest_map = {d.id: d.label for d in destinations}
    ext_map = {e.id: (e.name or e.extension_id) for e in extensions}

    destinations_data = [
        {"id": d.id, "label": d.label, "target": d.target, "enabled": d.enabled, "created_at": d.created_at.isoformat()}
        for d in destinations
    ]
    rules_data = [
        {
            "id": r.id,
            "destination_id": r.destination_id,
            "extension_id": r.extension_id,
            "event_type": r.event_type,
            "enabled": r.enabled,
            "created_at": r.created_at.isoformat(),
            "dest_label": dest_map.get(r.destination_id, "—"),
            "ext_name": ext_map.get(r.extension_id) if r.extension_id else None,
        }
        for r in rules
    ]
    extensions_data = [{"id": e.id, "name": e.name or e.extension_id, "store": e.store} for e in extensions]

    alert_log_data = await get_alert_log(current_user.id, session)

    return _render(
        request,
        "account.html",
        {
            "destinations": destinations_data,
            "rules": rules_data,
            "extensions": extensions_data,
            "alert_log": alert_log_data,
        },
        user=current_user,
    )


# ---------------------------------------------------------------------------
# Account — API keys
# ---------------------------------------------------------------------------


@router.get("/account/keys", response_class=HTMLResponse)
async def account_keys_page(
    request: Request,
    current_user: WebUser,
    session: SessionDep,
):
    keys = (
        await session.exec(select(ApiKey).where(ApiKey.user_id == current_user.id).order_by(ApiKey.created_at))
    ).all()
    keys_data = [
        {
            "id": k.id,
            "label": k.label,
            "key_prefix": k.key_prefix,
            "key_suffix": k.key_suffix,
            "readonly": k.readonly,
            "created_at": k.created_at.isoformat(),
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        }
        for k in keys
    ]
    return _render(request, "account_keys.html", {"keys": keys_data}, user=current_user)


# ---------------------------------------------------------------------------
# Account — change password
# ---------------------------------------------------------------------------


@router.get("/account/password", response_class=HTMLResponse)
async def account_password_page(
    request: Request,
    current_user: WebUser,
):
    return _render(request, "account_password.html", {}, user=current_user)


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------


@router.get("/help", response_class=HTMLResponse)
async def help_page(
    request: Request,
    current_user: WebUser,
):
    return _render(request, "help.html", {}, user=current_user)
