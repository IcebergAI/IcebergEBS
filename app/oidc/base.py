"""Provider-adapter contract + registry for OIDC SSO (#32).

An adapter turns a provider's ID-token/userinfo claims into a normalised
``OIDCIdentity``. Everything else about the flow (discovery, PKCE, state/nonce,
signature/issuer/audience validation) is handled generically by Authlib, so an
adapter is small: it knows only which claims a given IdP populates and how that
IdP conveys email verification and group membership.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class OIDCIdentity:
    """Normalised identity extracted from a validated ID token / userinfo."""

    # The validated token issuer (`iss`). A `subject` is unique only WITHIN its
    # issuer (OIDC spec), so the account key is (issuer, subject) — never the
    # admin-configurable adapter key, which could later point at a different issuer.
    issuer: str
    subject: str
    email: str
    email_verified: bool
    display_name: str
    groups: list[str] = field(default_factory=list)
    tenant_id: str | None = None


class OIDCAdapter(Protocol):
    """Per-provider claim mapping. Stateless; keyed by provider ``key``."""

    key: str

    def extract_identity(self, claims: dict[str, Any], role_claim: str) -> OIDCIdentity:
        """Map validated token claims to an OIDCIdentity.

        ``role_claim`` is the configured claim carrying the user's groups/roles
        ("" ⇒ no groups extracted). Raises ValueError if the required identity
        claims (sub/email, plus tenant provenance where required) are missing.
        """
        ...


class StandardOIDCAdapter:
    """Adapter for spec-compliant OIDC providers (Authentik, Auth0, Okta, …).

    Reads the standard claims: ``sub``, ``email`` (+ ``email_verified``), ``name``
    (falling back to ``preferred_username``), and groups/roles from the configured
    ``role_claim``. Entra needs its own adapter because its work/school tokens
    diverge (email fallback + email-verified policy).
    """

    def __init__(self, key: str) -> None:
        self.key = key

    def extract_identity(self, claims: dict[str, Any], role_claim: str) -> OIDCIdentity:
        issuer = _require(claims, "iss")
        subject = _require(claims, "sub")
        email = _require(claims, "email")
        display_name = str(claims.get("name") or claims.get("preferred_username") or email)
        return OIDCIdentity(
            issuer=issuer,
            subject=subject,
            email=email,
            email_verified=bool(claims.get("email_verified", False)),
            display_name=display_name,
            groups=_groups_from(claims, role_claim),
        )


def _require(claims: dict[str, Any], *names: str) -> str:
    for name in names:
        value = claims.get(name)
        if value:
            return str(value)
    raise ValueError(f"ID token missing required claim(s): {' / '.join(names)}")


def _role_claim_overaged(claims: dict[str, Any], role_claim: str) -> bool:
    """True when the configured groups/roles claim was displaced into an OIDC
    distributed claim rather than delivered inline.

    Microsoft Entra ID omits the group/role payload once a user is in more than
    ~200 groups and instead emits ``_claim_names``/``_claim_sources`` pointing at
    Microsoft Graph (the "groups overage" contract). The overage indicator is
    **always keyed on ``groups``** in ``_claim_names`` — even when membership is
    emitted into the ``roles`` claim via the ``emit_as_roles`` optional-claim
    setting — so a configured ``role_claim`` of either ``groups`` or ``roles`` is
    affected. Reading the absent claim as "no groups" would silently demote an
    IdP-managed admin and revoke their sessions (#227); treat it as an extraction
    failure instead.

    Gated on ``role_claim`` being configured **and not delivered inline**: a
    deployment that doesn't map groups/roles is unaffected, and an inline value
    (even an empty list) is trusted over the overage pointer, so a present role
    source (e.g. genuine app roles) never trips a false-positive deny.
    """
    if not role_claim or role_claim in claims:
        return False
    names = claims.get("_claim_names")
    if not isinstance(names, dict):
        return False
    return role_claim in names or "groups" in names


def _groups_from(claims: dict[str, Any], role_claim: str) -> list[str]:
    if not role_claim:
        return []
    raw = claims.get(role_claim)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple)):
        return [str(g) for g in raw]
    return [str(raw)]


# Populated at import time by the adapter modules registering themselves.
_REGISTRY: dict[str, OIDCAdapter] = {}


def register_adapter(adapter: OIDCAdapter) -> None:
    _REGISTRY[adapter.key] = adapter


def get_adapter(key: str) -> OIDCAdapter | None:
    return _REGISTRY.get(key)
