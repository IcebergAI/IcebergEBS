from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Callable
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import and_, func
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app import oidc_settings, proxy_settings
from app.alert_queries import get_alert_log
from app.auth import (
    authenticate_session,
    clear_oidc_id_token,
    clear_session,
    get_current_user,
    get_oidc_id_token,
    set_session,
    verify_credentials,
)
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
from app.findings_view import group_detection_findings
from app.inspector import PackageAnalysis
from app.models import AlertDestination, AlertRule, ApiKey, Extension, FetchLog, InstallObservation, User
from app.oidc import service as oidc_service
from app.oidc.config import EDITABLE_FIELDS as OIDC_EDITABLE_FIELDS
from app.oidc.config import client_secret_status
from app.permissions import host_permission_tier, permission_tier
from app.ratelimit import login_limiter
from app.retention import freshness_cutoff
from app.scoring import risk_level
from app.threat_intel import build_threat_intel_indicators
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
    # Pre-stamp <html data-theme> from the cookie static/js/theme-boot.js maintains,
    # so the first server-rendered frame is already the right theme; the (external,
    # synchronous) theme-boot script then re-resolves a 'system' preference against
    # the current OS setting before first paint (#106).
    resolved_theme = request.cookies.get("ebs_resolved_theme")
    ctx["initial_theme"] = resolved_theme if resolved_theme in ("light", "dark") else "light"
    response = templates.TemplateResponse(request=request, name=template, context=ctx)
    if flash:
        _clear_flash(response)
    return response


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------


def _login_context(error: str | None) -> dict:
    """Shared login-page context: SSO buttons + which login paths are enabled (#32)."""
    oidc_service.ensure_registered()
    cfg = oidc_settings.get_config()
    return {
        "error": error,
        "local_auth_enabled": cfg.local_auth_enabled,
        "sso_providers": [(p.key, p.display_name) for p in oidc_service.registered_providers()],
    }


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, session: SessionDep):
    # DB-backed validation, matching require_auth — a signature-valid cookie whose
    # user was deleted or whose password changed on another device must NOT redirect
    # to "/" (require_auth would bounce it straight back here → infinite loop, #73).
    if await authenticate_session(request, session):
        return RedirectResponse("/", status_code=303)
    error = None
    if request.query_params.get("error") == "sso":
        # The OIDC callback redirects here on any auth failure; the detail is
        # logged server-side only (it can name providers/reasons an anonymous
        # visitor shouldn't see).
        error = "Single sign-on failed. Try again or contact your administrator."
    # Clear any stale-but-signed cookie so it can't keep failing require_auth.
    response = _render(request, "login.html", _login_context(error))
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
    # Break-glass gating (#32): in OIDC-only mode the password path is refused
    # outright (the form isn't rendered either, but the endpoint must not trust that).
    if not oidc_settings.get_config().local_auth_enabled:
        response = _render(request, "login.html", _login_context("Local sign-in is disabled — use single sign-on."))
        response.status_code = 403
        return response

    # App-level brute-force throttle, independent of the edge proxy (M3 / #8).
    key = login_limiter.key(request.client.host if request.client else None, username)
    retry_after = login_limiter.retry_after(key)
    if retry_after is not None:
        response = _render(
            request,
            "login.html",
            _login_context("Too many failed attempts — please try again later."),
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
    return _render(request, "login.html", _login_context("Invalid credentials"))


def _post_logout_redirect_uri(request: Request) -> str:
    """Absolute /login URL the IdP returns to after RP-initiated logout — the same
    base resolution as the OIDC callback (configured base, else the request)."""
    base = oidc_settings.get_config().oidc_redirect_base_url or settings.app_base_url
    base = base.rstrip("/") if base else str(request.base_url).rstrip("/")
    return f"{base}/login"


@router.post("/logout")
async def logout(request: Request, user: WebUser):
    # For an SSO account, additionally end the session at the IdP (RP-initiated
    # logout, #221) so logout isn't merely local. Best-effort: if the provider has
    # no end_session_endpoint or is unreachable, fall through to the local logout —
    # the local cookies are always cleared, and logout never 500s.
    id_token = get_oidc_id_token(request)
    target = "/login"
    if user.oidc_subject is not None:
        idp_url = await oidc_service.end_session_url(
            user.auth_provider,
            post_logout_redirect_uri=_post_logout_redirect_uri(request),
            id_token=id_token,
        )
        if idp_url:
            target = idp_url
    response = RedirectResponse(target, status_code=303)
    clear_session(response)
    clear_oidc_id_token(response)
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
        # Band computed server-side from scoring.risk_level — the single home of
        # the 75/50/25 thresholds. The dashboard JS maps band → CSS class; the
        # colours live only in app.css's --risk-* tokens (#105).
        "risk_band": risk_level(e.risk_score) or "unknown",
        "watchlist": e.watchlist,
    }


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


def _is_stale(watchlist: bool, last_fetched_at, now: datetime, stale_after: timedelta) -> bool:
    """Whether a watchlist extension is stale — gone longer than ``stale_after``
    without a successful refresh (a never-fetched watchlist extension counts as
    stale). Non-watchlist extensions are never stale. Pure, so the fetch-health
    rules are unit-testable without the dashboard route (#165)."""
    if not watchlist:
        return False
    if last_fetched_at is None:
        return True
    if last_fetched_at.tzinfo is None:
        last_fetched_at = last_fetched_at.replace(tzinfo=timezone.utc)
    return (now - last_fetched_at) > stale_after


@dataclass
class FleetStats:
    extensions_count: int
    high_risk: int
    watchlist_count: int
    last_refresh: datetime | None
    next_refresh: datetime | None
    unhealthy: int
    # Most-recent FetchLog per extension, computed once here and reused by the
    # dashboard's per-row table annotation so the query isn't run twice.
    latest_logs: dict[int, FetchLog]


async def _fleet_stats(session: AsyncSession, user_id: int, now: datetime, stale_after: timedelta) -> FleetStats:
    """Filter-independent fleet snapshot for the stat tiles: counts + fetch health.

    Column-only (no JSON blobs loaded). ``unhealthy`` counts watchlist extensions
    whose latest fetch failed for a reason that is the extension's fault — a
    store-outage circuit-breaker skip (#108) is excluded — or that have gone
    stale. Extracted from ``dashboard()`` so the counting rules are unit-testable
    without spinning up the route (#165)."""
    snapshot = (
        await session.exec(
            select(Extension.id, Extension.risk_score, Extension.watchlist, Extension.last_fetched_at).where(
                Extension.user_id == user_id
            )
        )
    ).all()
    latest_logs = await _latest_fetch_logs(session, [r.id for r in snapshot])

    fetched = [r.last_fetched_at for r in snapshot if r.last_fetched_at]
    last_refresh = max(fetched) if fetched else None
    next_refresh = last_refresh + timedelta(minutes=settings.fetch_interval_minutes) if last_refresh else None

    unhealthy = 0
    for r in snapshot:
        log = latest_logs.get(r.id)
        # A store-outage skip (circuit breaker, #108) is not the extension's fault,
        # so it doesn't count as "failing" — a brief store blip must not spike the
        # tile. A prolonged outage still surfaces via the staleness check below.
        failing = log is not None and not log.success and not log.store_outage
        if r.watchlist and (failing or _is_stale(r.watchlist, r.last_fetched_at, now, stale_after)):
            unhealthy += 1

    return FleetStats(
        extensions_count=len(snapshot),
        # "High & critical" = at/above the high band's floor — from RISK_BANDS (the
        # render-side mirror of scoring.risk_level), never a re-inlined cut point (#281).
        high_risk=sum(1 for r in snapshot if r.risk_score is not None and r.risk_score >= RISK_BANDS["high"][0]),
        watchlist_count=sum(1 for r in snapshot if r.watchlist),
        last_refresh=last_refresh,
        next_refresh=next_refresh,
        unhealthy=unhealthy,
        latest_logs=latest_logs,
    )


async def _top_exposure(session: AsyncSession, user_id: int) -> list[dict]:
    """Top-5 extensions by exposure ("blast radius", #29): risk × org footprint,
    highest first. Column-only select like the fleet snapshot; only extensions
    with a known footprint and score qualify (exposure is NULL otherwise)."""
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
                Extension.user_id == user_id,
                Extension.install_footprint.is_not(None),
                Extension.install_footprint > 0,
                Extension.risk_score.is_not(None),
            )
            .order_by(EXPOSURE_EXPR.desc())
            .limit(5)
        )
    ).all()
    return [
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


def _build_qs(base_params: dict) -> Callable[..., str]:
    """Return a helper that builds a relative dashboard URL preserving the current
    filter/sort/page state with selective overrides (None drops a param), dropping
    empty values and the defaults (page 1, risk_score sort, desc order) to keep
    URLs clean. Passed to the template for filter pills, sort headers and
    pagination links."""

    def qs(**overrides) -> str:
        params = {**base_params, **overrides}
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        if clean.get("page") == 1:
            clean.pop("page", None)
        if clean.get("sort") == "risk_score":
            clean.pop("sort", None)
        if clean.get("order") == "desc":
            clean.pop("order", None)
        return "/?" + urlencode(clean) if clean else "/"

    return qs


def _export_url(fmt: str, *, store, risk, q, sort, order) -> str:
    """Build the CSV/JSON export URL honouring the active filters/sort (but not
    pagination)."""
    params = {"format": fmt, "store": store, "risk": risk, "q": q, "sort": sort, "order": order}
    clean = {k: v for k, v in params.items() if v not in (None, "")}
    return "/api/extensions/export?" + urlencode(clean)


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
    page: str = "1",
):
    # Tolerate junk query params from the UI (don't 422 a browser) — fall back
    # to defaults rather than rejecting. `page` is a str for the same reason: a
    # mangled / hand-edited `?page=abc` must render the dashboard, not raw-422 the
    # way a typed `int` param would (#152).
    if store not in ("chrome", "vscode", "edge"):
        store = None
    if risk not in RISK_BANDS:
        risk = None
    if sort not in SORT_COLUMNS:
        sort = "risk_score"
    if order not in ("asc", "desc"):
        order = "desc"
    q = (q or "").strip() or None
    try:
        page = max(int(page), 1)
    except (TypeError, ValueError):
        page = 1

    now = datetime.now(timezone.utc)
    stale_after = _stale_after()

    # Filter-independent stat tiles (counts + fetch health) and the top-exposure
    # panel — each owns its column-only query so the counting rules are testable
    # in isolation (#165).
    stats = await _fleet_stats(session, current_user.id, now, stale_after)
    top_exposure = await _top_exposure(session, current_user.id)

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
        log = stats.latest_logs.get(e.id)
        d = _ext_to_dict(e)
        d["last_fetch_ok"] = log.success if log is not None else None
        d["last_fetch_error"] = log.error_message if (log is not None and not log.success) else None
        d["store_outage"] = bool(log.store_outage) if log is not None else False
        d["stale"] = _is_stale(e.watchlist, e.last_fetched_at, now, stale_after)
        ext_dicts.append(d)

    showing_from = offset + 1 if filtered_total else 0
    showing_to = offset + len(ext_dicts)

    base_params = {"store": store, "risk": risk, "q": q, "sort": sort, "order": order, "page": page}
    qs = _build_qs(base_params)

    return _render(
        request,
        "dashboard.html",
        {
            "qs": qs,
            "export_csv_url": _export_url("csv", store=store, risk=risk, q=q, sort=sort, order=order),
            "export_json_url": _export_url("json", store=store, risk=risk, q=q, sort=sort, order=order),
            "extensions": ext_dicts,
            "top_exposure": top_exposure,
            "extensions_count": stats.extensions_count,
            "high_risk_count": stats.high_risk,
            "watchlist_count": stats.watchlist_count,
            "unhealthy_count": stats.unhealthy,
            "last_refresh_label": _ago(stats.last_refresh),
            "next_refresh_label": (
                f"next ~{stats.next_refresh.strftime('%H:%M')} UTC" if stats.next_refresh else "next: scheduled"
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


# Score-breakdown row definitions for the detail page: (label, risk_detail key,
# category max, note). Rendered via `risk_rows` in extension_detail.
_RISK_ROW_DEFS = [
    ("Permissions", "permissions", 25, "Danger level of declared permissions"),
    ("Popularity", "popularity", 20, "Install count / sudden drop"),
    ("Publisher", "publisher", 15, "Ownership change / verification"),
    ("Staleness", "staleness", 15, "Time since last author update"),
    ("Code behaviour", "code_behaviour", 15, "eval / remote code / obfuscation"),
    ("External domains", "external_domains", 10, "Unknown external URLs in code"),
]


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

    # The Extension accessors own the defensive parse — a partial write or manual DB edit
    # can't 500 the detail page; they log + fall back, including on valid-but-wrong-shape
    # JSON (#61/#150 hardening, #167).
    permissions = ext.permissions_list()
    risk_detail = ext.risk_detail_dict()
    package_analysis = ext.analysis_dict()

    host_permissions = []
    if package_analysis:
        # Backfill any keys a partial write / older schema left missing, so the
        # detail page renders without KeyErrors. Defaults are derived from the
        # PackageAnalysis field defaults, so they can't drift from what
        # to_json_dict stores (#164, #61).
        for key, default in PackageAnalysis.stored_defaults().items():
            package_analysis.setdefault(key, default)
        if not isinstance(package_analysis.get("findings"), list):
            package_analysis["findings"] = []
        package_analysis["grouped_findings"] = group_detection_findings(package_analysis["findings"])
        # Mirror the API DTO's guard (#150): a wrong-shaped stored value — non-list
        # container or non-string members — must not reach the tier classifier, whose
        # set-membership check raises TypeError on unhashable members (#281 review).
        raw_hosts = package_analysis.get("host_permissions", [])
        host_permissions = [h for h in raw_hosts if isinstance(h, str)] if isinstance(raw_hosts, list) else []
    # Tier every rendered permission tag from the app.permissions sets — the single
    # source shared with the scorer/inspector (#63) — instead of Jinja re-inlining
    # the tier lists (which had drifted, #281).
    permission_tags = [{"name": p, "tier": permission_tier(p)} for p in permissions]
    host_permission_tags = [{"name": p, "tier": host_permission_tier(p)} for p in host_permissions]

    # Score-breakdown rows, banded server-side via risk_level over the category
    # percentage — the same 75/50/25 cut points as everywhere else (#281); the
    # template must not re-inline them.
    risk_rows = []
    if risk_detail:
        for label, key, category_max, note in _RISK_ROW_DEFS:
            value = risk_detail.get(key) or 0
            pct = round(value / category_max * 100, 1)
            risk_rows.append(
                {
                    "label": label,
                    "value": value,
                    "max": category_max,
                    "note": note,
                    "pct": pct,
                    "band": risk_level(int(pct)),
                }
            )

    threat_intel_indicators = build_threat_intel_indicators(package_analysis)
    threat_intel_primary_indicators = [
        indicator for indicator in threat_intel_indicators if indicator.get("section") != "referenced"
    ]
    threat_intel_referenced_indicators = [
        indicator for indicator in threat_intel_indicators if indicator.get("section") == "referenced"
    ]
    score_history = {
        "points": [
            {"d": log.fetched_at.strftime("%b %d"), "s": log.risk_score_after}
            for log in reversed(fetch_logs)
            if log.success and log.risk_score_after is not None
        ],
        # Band geometry for the trend chart, derived from RISK_BANDS (which
        # mirrors scoring.risk_level — the single home of the thresholds). The
        # chart colours its line/dots/shading from this payload and must never
        # re-inline the cut points in JS (#105 review).
        "bands": [
            {"band": band, "from": low, "to": 100 if high is None else high} for band, (low, high) in RISK_BANDS.items()
        ],
    }

    # Org footprint (#29): SOAR-reported installs grouped by department. The
    # headline count reuses the cached install_footprint (distinct assets); the
    # breakdown is queried live over FRESH observations only (#287), matching the
    # freshness window the cached footprint is computed with — otherwise the card
    # total and its per-department rows could disagree.
    dept_stmt = (
        select(
            InstallObservation.department,
            func.count(func.distinct(InstallObservation.asset_id)).label("n"),
        )
        .where(InstallObservation.extension_id == ext_id)
        .group_by(InstallObservation.department)
        .order_by(func.count(func.distinct(InstallObservation.asset_id)).desc())
    )
    cutoff = freshness_cutoff()
    if cutoff is not None:
        dept_stmt = dept_stmt.where(InstallObservation.last_seen >= cutoff)
    dept_rows = (await session.exec(dept_stmt)).all()
    footprint_assets = ext.install_footprint or 0
    footprint_departments = [{"department": d.department or "Unassigned", "count": d.n} for d in dept_rows]
    exposure = ext.risk_score * footprint_assets if (ext.risk_score is not None and footprint_assets) else None

    return _render(
        request,
        "extension_detail.html",
        {
            "ext": ext,
            # Band from scoring.risk_level (the single home of the thresholds);
            # the template maps it to --risk-* token classes (#105).
            "risk_band": risk_level(ext.risk_score) or "unknown",
            "footprint_assets": footprint_assets,
            "footprint_departments": footprint_departments,
            "exposure": exposure,
            "permission_tags": permission_tags,
            "host_permission_tags": host_permission_tags,
            "risk_detail": risk_detail,
            "risk_rows": risk_rows,
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
            "auth_provider": u.auth_provider,
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
# Admin — outbound proxy (#216)
# ---------------------------------------------------------------------------


@router.get("/admin/proxy", response_class=HTMLResponse)
async def admin_proxy_page(
    request: Request,
    current_user: AdminUserUI,
    session: SessionDep,
):
    row = await proxy_settings.get_settings(session)
    return _render(
        request,
        "admin_proxy.html",
        {
            "proxy_data": {
                "mode": row.mode,
                "proxy_url": row.proxy_url,
                "no_proxy": row.no_proxy,
                "updated_at": row.updated_at.isoformat(),
            },
        },
        user=current_user,
    )


# ---------------------------------------------------------------------------
# Admin — single sign-on (#32)
# ---------------------------------------------------------------------------


@router.get("/admin/oidc", response_class=HTMLResponse)
async def admin_oidc_page(
    request: Request,
    current_user: AdminUserUI,
    session: SessionDep,
):
    row = await oidc_settings.get_settings(session)
    return _render(
        request,
        "admin_oidc.html",
        {
            "oidc_data": {
                "settings": {f: getattr(row, f) for f in OIDC_EDITABLE_FIELDS},
                # Booleans only — the secret values are env-only and never rendered.
                "client_secrets_set": client_secret_status(),
                "updated_at": row.updated_at.isoformat(),
            },
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
    # SSO-provisioned accounts have no local password to change (#32); the
    # template swaps the form for an explanatory note.
    return _render(
        request,
        "account_password.html",
        {"has_local_password": bool(current_user.password_hash)},
        user=current_user,
    )


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------


@router.get("/help", response_class=HTMLResponse)
async def help_page(
    request: Request,
    current_user: WebUser,
):
    return _render(request, "help.html", {}, user=current_user)
