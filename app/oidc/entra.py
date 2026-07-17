"""Microsoft Entra ID adapter (#32).

Account identity is the validated token's stable ``sub`` plus immutable tenant
``tid``. Human-readable ``email``/``preferred_username`` claims are display and
contact attributes only; they never identify or auto-link an existing account.
An email is verified only when Entra explicitly asserts verification.
"""

from __future__ import annotations

from typing import Any

from app.oidc.base import (
    OIDCIdentity,
    _groups_from,
    _require,
    _role_claim_overaged,
    register_adapter,
)


class EntraAdapter:
    key = "entra"

    def extract_identity(self, claims: dict[str, Any], role_claim: str) -> OIDCIdentity:
        issuer = _require(claims, "iss")
        subject = _require(claims, "sub")
        tenant_id = _require(claims, "tid")
        email = _require(claims, "email", "preferred_username")
        has_email_claim = bool(claims.get("email"))
        edov = claims.get("xms_edov")
        if edov is not None:
            email_verified = edov is True
        else:
            email_verified = claims.get("email_verified") is True
        # xms_edov/email_verified apply to an asserted email, not to the mutable
        # preferred_username fallback.
        email_verified = has_email_claim and email_verified
        if _role_claim_overaged(claims, role_claim):
            # Entra groups-overage (>~200 groups): the ID token carries
            # _claim_names/_claim_sources instead of an inline groups array. Fail
            # CLOSED rather than reading it as "no groups" — that would demote an
            # IdP-managed admin and revoke their sessions on an otherwise-successful
            # login (#227). The callback turns this into a logged /login?error=sso.
            raise ValueError(
                f"groups claim '{role_claim}' delivered as an Entra overage/"
                "distributed claim (_claim_names); no inline groups in the ID "
                "token — configure the Entra app to emit only assigned groups "
                "(Token configuration -> Groups -> 'Groups assigned to the "
                "application') to avoid the >200-group overage"
            )
        display_name = str(claims.get("name") or email)
        return OIDCIdentity(
            issuer=issuer,
            subject=subject,
            email=email,
            email_verified=email_verified,
            display_name=display_name,
            groups=_groups_from(claims, role_claim),
            tenant_id=tenant_id,
        )


register_adapter(EntraAdapter())
