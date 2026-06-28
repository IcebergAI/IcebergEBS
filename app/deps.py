"""Reusable FastAPI dependency aliases.

Per FastAPI guidance, declare each `Annotated[..., Depends(...)]` once and reuse it
across path operations instead of repeating the full form in every signature.
"""

from typing import Annotated

from fastapi import Depends
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import require_admin, require_admin_ui, require_api_auth, require_auth
from app.database import get_session
from app.models import User

# Database session (one per request).
SessionDep = Annotated[AsyncSession, Depends(get_session)]

# Authenticated user via the JSON API path (Bearer token or session cookie) — raises
# 401/403, never redirects.
CurrentUser = Annotated[User, Depends(require_api_auth)]

# Authenticated user via the session cookie for HTML routes — redirects to /login.
WebUser = Annotated[User, Depends(require_auth)]

# Admin-only variants of the two above.
AdminUser = Annotated[User, Depends(require_admin)]
AdminUserUI = Annotated[User, Depends(require_admin_ui)]
