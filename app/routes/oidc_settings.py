"""Admin JSON API for the SSO/OIDC runtime config (#32).

Settings CRUD on the singleton OIDCSettings row. Client secrets are env-only:
the PUT model is ``extra="forbid"`` so a payload smuggling a ``*_client_secret``
key is a 422, not silently dropped, and responses expose only per-provider
``client_secrets_set`` booleans — never the values.
"""

from datetime import datetime
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, field_validator
from sqlmodel.ext.asyncio.session import AsyncSession

from app import oidc_settings
from app.deps import AdminUser, SessionDep
from app.oidc.config import EDITABLE_FIELDS, client_secret_status

router = APIRouter(prefix="/api", tags=["sso"])


class OIDCSettingsUpdate(BaseModel):
    # extra="forbid": a PUT smuggling a client-secret key is a 422, not silently
    # dropped — secrets are env-only by construction (see app/config.py #32).
    model_config = ConfigDict(extra="forbid")

    auth_mode: str | None = None
    oidc_redirect_base_url: str | None = None
    oidc_entra_enabled: bool | None = None
    oidc_entra_client_id: str | None = None
    oidc_entra_tenant_id: str | None = None
    oidc_entra_scopes: str | None = None
    oidc_entra_role_claim: str | None = None
    oidc_entra_role_map: str | None = None
    oidc_authentik_enabled: bool | None = None
    oidc_authentik_client_id: str | None = None
    oidc_authentik_base_url: str | None = None
    oidc_authentik_app_slug: str | None = None
    oidc_authentik_scopes: str | None = None
    oidc_authentik_role_claim: str | None = None
    oidc_authentik_role_map: str | None = None
    oidc_auth0_enabled: bool | None = None
    oidc_auth0_client_id: str | None = None
    oidc_auth0_domain: str | None = None
    oidc_auth0_scopes: str | None = None
    oidc_auth0_role_claim: str | None = None
    oidc_auth0_role_map: str | None = None
    oidc_okta_enabled: bool | None = None
    oidc_okta_client_id: str | None = None
    oidc_okta_domain: str | None = None
    oidc_okta_auth_server: str | None = None
    oidc_okta_scopes: str | None = None
    oidc_okta_role_claim: str | None = None
    oidc_okta_role_map: str | None = None

    @field_validator("*")
    @classmethod
    def _strip_strings(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator("auth_mode")
    @classmethod
    def _normalize_mode(cls, value: str | None) -> str | None:
        return value.lower() if value is not None else None

    @field_validator("oidc_redirect_base_url", "oidc_authentik_base_url")
    @classmethod
    def _absolute_url(cls, value: str | None) -> str | None:
        if not value:
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL must be an absolute http(s) URL")
        return value.rstrip("/")

    @field_validator("oidc_auth0_domain", "oidc_okta_domain")
    @classmethod
    def _domain_only(cls, value: str | None) -> str | None:
        if not value:
            return value
        if "://" in value or "/" in value or not urlsplit(f"https://{value}").hostname:
            raise ValueError("Domain must contain a hostname only")
        return value


class OIDCSettingsOut(BaseModel):
    """Editable fields + secret status; never the secrets themselves."""

    settings: dict
    client_secrets_set: dict[str, bool]
    updated_at: datetime


async def _public_settings(session: AsyncSession) -> OIDCSettingsOut:
    row = await oidc_settings.get_settings(session)
    return OIDCSettingsOut(
        settings={f: getattr(row, f) for f in EDITABLE_FIELDS},
        client_secrets_set=client_secret_status(),
        updated_at=row.updated_at,
    )


@router.get("/oidc/settings")
async def get_oidc_settings(_: AdminUser, session: SessionDep) -> OIDCSettingsOut:
    return await _public_settings(session)


@router.put("/oidc/settings")
async def put_oidc_settings(body: OIDCSettingsUpdate, _: AdminUser, session: SessionDep) -> OIDCSettingsOut:
    # Validation runs inside update_settings, on the RESULTING config under a
    # FOR UPDATE row lock — a route-level pre-check would be a TOCTOU against a
    # concurrent PUT (e.g. one sets auth_mode=oidc while another disables the last
    # complete provider; each pre-check passes, the merge locks everyone out).
    try:
        await oidc_settings.update_settings(session, body.model_dump(exclude_unset=True))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    return await _public_settings(session)
