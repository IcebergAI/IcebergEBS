"""Reusable FastAPI dependency aliases.

Per FastAPI guidance, declare each `Annotated[..., Depends(...)]` once and reuse it
across path operations instead of repeating the full form in every signature.
"""

from typing import Annotated, TypeVar

from fastapi import Depends, HTTPException
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_api_auth, require_auth, require_role, require_role_ui, require_session_user
from app.database import get_session
from app.models import Role, User

# Database session (one per request).
SessionDep = Annotated[AsyncSession, Depends(get_session)]

_T = TypeVar("_T")


async def get_owned_or_404(
    session: AsyncSession,
    model: type[_T],
    obj_id: int,
    user_id: int,
    *,
    detail: str = "Not found",
    for_update: bool = False,
) -> _T:
    """Load ``model`` row ``obj_id`` and assert it belongs to ``user_id``, else 404.

    Consolidates the owner-scoped fetch gate that was repeated ~12× across the JSON
    API routes (``api.py`` / ``alerts.py`` / ``keys.py``) — one place to change if
    the semantics ever do (admin override, audit-on-denied-access, 403-vs-404).
    A missing row and another user's row both return the same 404 so ownership
    can't be probed. Returns the row for the caller to use.

    ``for_update`` takes a ``SELECT … FOR UPDATE`` row lock and refreshes the loaded
    attributes (``with_for_update=True, populate_existing=True``) — the #217 pattern
    for a read-validate-write that must not race a concurrent writer. Without
    ``populate_existing`` SQLAlchemy would return an already-identity-mapped instance
    with stale attributes, so the queued writer would validate pre-commit state.

    HTML routes that redirect-and-flash on a miss (``ui.py``) intentionally keep
    their own handling — this helper is for the JSON 404 gate only (#169).
    """
    if for_update:
        obj = await session.get(model, obj_id, with_for_update=True, populate_existing=True)
    else:
        obj = await session.get(model, obj_id)
    if obj is None or getattr(obj, "user_id", None) != user_id:
        raise HTTPException(status_code=404, detail=detail)
    return obj


# Authenticated user via the JSON API path (Bearer token or session cookie) — raises
# 401/403, never redirects.
CurrentUser = Annotated[User, Depends(require_api_auth)]

# Authenticated user via the session cookie for HTML routes — redirects to /login.
WebUser = Annotated[User, Depends(require_auth)]

# Interactive session cookie only (Bearer rejected) for JSON routes that mint
# credentials — POST /api/keys, so a bearer key can't self-renew (#278 review).
# Raises JSON 401, never redirects.
SessionUser = Annotated[User, Depends(require_session_user)]

# Role gates (#33). Each is an EXPLICIT allowed set (see auth.require_role) —
# pick the narrowest one that fits the route:
#
#   AdminUser     users, alert destinations + rules, settings, threat-list ingest
#   AnalystUser   every extension mutation (add / bulk / inventory / delete / refresh /
#                 watchlist / triage) — admin OR analyst
#   AuditReader   the audit trail — admin OR auditor (an auditor's whole purpose;
#                 an analyst does not get to read other users' actions)
#
# Reads stay on CurrentUser: the auditor role is "read everything, change nothing".
# Self-service credential routes (own password, own API keys) also stay on
# CurrentUser/SessionUser — an auditor must be able to rotate a leaked secret.
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]
AnalystUser = Annotated[User, Depends(require_role(Role.ADMIN, Role.ANALYST))]
AuditReader = Annotated[User, Depends(require_role(Role.ADMIN, Role.AUDITOR))]

# HTML counterparts (303 redirects instead of JSON 401/403).
AdminUserUI = Annotated[User, Depends(require_role_ui(Role.ADMIN))]
AnalystUserUI = Annotated[User, Depends(require_role_ui(Role.ADMIN, Role.ANALYST))]
AuditReaderUI = Annotated[User, Depends(require_role_ui(Role.ADMIN, Role.AUDITOR))]
