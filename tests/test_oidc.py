"""OIDC / SSO tests (#32).

The Authlib client is always stubbed — no discovery/JWKS/token network calls. The
Authentik provider is enabled for the whole suite in conftest, so the routes are
registered and ``get_provider("authentik")`` resolves.
"""

from dataclasses import replace
from datetime import datetime, timezone

import httpx
import pytest
from authlib.integrations.starlette_client import OAuthError

from app import oidc_settings
from app.auth import _session_after_password_change, create_session_cookie, verify_credentials
from app.config import settings
from app.models import User
from app.oidc import service as oidc_service
from app.oidc.base import OIDCIdentity, get_adapter
from app.oidc.config import OIDCProviderConfig, env_config, validate_config
from app.oidc.entra import EntraAdapter
from app.oidc.service import _NonClosingTransport, map_is_admin, provision_oidc_user


def _cfg(role_map: dict[str, str] | None = None) -> OIDCProviderConfig:
    return OIDCProviderConfig(
        key="authentik",
        display_name="Authentik",
        client_id="c",
        client_secret="s",
        metadata_url="https://authentik.test/application/o/iceberg-ebs/.well-known/openid-configuration",
        role_claim="groups",
        role_map=role_map or {},
    )


def _identity(**overrides) -> OIDCIdentity:
    base = {
        "issuer": "https://idp.test/",
        "subject": "sub-1",
        "email": "new@sso.test",
        "email_verified": True,
        "display_name": "New User",
        "groups": [],
    }
    base.update(overrides)
    return OIDCIdentity(**base)


class _FakeOIDCClient:
    """Stands in for an Authlib StarletteOAuth2App — no network."""

    def __init__(self, claims=None, error=None, redirect="https://authentik.test/authorize?x=1", redirect_error=None):
        self._claims = claims
        self._error = error
        self._redirect = redirect
        self._redirect_error = redirect_error

    async def authorize_redirect(self, request, redirect_uri):
        from fastapi.responses import RedirectResponse

        if self._redirect_error:
            raise self._redirect_error
        return RedirectResponse(self._redirect)

    async def authorize_access_token(self, request):
        if self._error:
            raise self._error
        # token["userinfo"] carries the ID-token claims Authlib validated; None
        # here models a token response Authlib could not ID-token-validate.
        return {"userinfo": self._claims}


@pytest.fixture(name="patch_oidc")
def patch_oidc_fixture(monkeypatch):
    """Install a stub Authlib client for every provider lookup."""

    def _install(client: _FakeOIDCClient) -> None:
        oidc_service.ensure_registered()
        monkeypatch.setattr(oidc_service.oauth, "create_client", lambda name: client)

    return _install


def _claims(**overrides) -> dict:
    base = {
        "iss": "https://idp.test/",
        "sub": "sub-route-1",
        "email": "route@sso.test",
        "email_verified": True,
        "name": "Route User",
        "groups": [],
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Provisioning policy (service-level)
# --------------------------------------------------------------------------- #


async def test_jit_creates_non_admin_user(session):
    user, created = await provision_oidc_user(session, cfg=_cfg(), identity=_identity())
    assert created is True
    assert user.username == "new@sso.test"
    assert user.email == "new@sso.test"
    assert user.password_hash is None
    assert user.is_admin is False
    assert user.auth_provider == "authentik"
    assert user.oidc_subject == "sub-1"
    assert user.role_managed_by_idp is True


async def test_role_map_grants_admin(session):
    cfg = _cfg(role_map={"ebs-admins": "admin"})
    user, _ = await provision_oidc_user(session, cfg=cfg, identity=_identity(groups=["ebs-admins"]))
    assert user.is_admin is True


def test_map_is_admin_any_match_and_no_self_elevation():
    cfg = _cfg(role_map={"a": "user", "b": "admin"})
    # Any-match: group order (IdP-controlled) must not matter for the boolean.
    assert map_is_admin(cfg, _identity(groups=["a", "b"])) is True
    assert map_is_admin(cfg, _identity(groups=["b", "a"])) is True
    assert map_is_admin(cfg, _identity(groups=["a"])) is False
    # Unmapped groups and an empty map never elevate.
    assert map_is_admin(cfg, _identity(groups=["unmapped"])) is False
    assert map_is_admin(_cfg(), _identity(groups=["ebs-admins"])) is False


async def test_returning_user_not_duplicated(session):
    first, created_first = await provision_oidc_user(session, cfg=_cfg(), identity=_identity())
    second, created_second = await provision_oidc_user(session, cfg=_cfg(), identity=_identity())
    assert created_first is True and created_second is False
    assert first.id == second.id


async def test_returning_admin_sync_up_and_down_bumps_session_cutoff(session, monkeypatch):
    from datetime import timedelta

    import app.oidc.service as service_module

    cfg = _cfg(role_map={"ebs-admins": "admin"})
    user, _ = await provision_oidc_user(session, cfg=cfg, identity=_identity(groups=["ebs-admins"]))
    assert user.is_admin is True

    # Cookie minted under the admin authorization state.
    issued_at = datetime.now(timezone.utc)

    # Place the sync deterministically AFTER the cookie (the cutoff comparison
    # has a 1s tolerance for the serializer's whole-second timestamps).
    monkeypatch.setattr(service_module, "_utcnow", lambda: datetime.now(timezone.utc) + timedelta(seconds=10))
    demoted, _ = await provision_oidc_user(session, cfg=cfg, identity=_identity(groups=[]))

    assert demoted.id == user.id
    assert demoted.is_admin is False
    # The pre-sync cookie is now stale (password_changed_at is the generic cutoff).
    assert _session_after_password_change(demoted, issued_at) is False

    # Sync back up on re-adding the group.
    promoted, _ = await provision_oidc_user(session, cfg=cfg, identity=_identity(groups=["ebs-admins"]))
    assert promoted.is_admin is True


async def test_locally_managed_user_never_synced(session):
    """A locally-created account (role_managed_by_idp=False) keeps its admin flag."""
    local_admin = User(
        username="breakglass@sso.test",
        password_hash="x",
        email=None,
        is_admin=True,
        auth_provider="authentik",
        oidc_issuer="https://idp.test/",
        oidc_subject="sub-breakglass",
        role_managed_by_idp=False,
    )
    session.add(local_admin)
    await session.commit()

    user, created = await provision_oidc_user(
        session, cfg=_cfg(role_map={"ebs-admins": "admin"}), identity=_identity(subject="sub-breakglass", groups=[])
    )
    assert created is False
    assert user.is_admin is True  # not demoted despite no admin group


async def test_email_collision_with_local_account_denied(session):
    session.add(User(username="victim", password_hash="x", email="admin@corp.test", is_admin=True))
    await session.commit()

    with pytest.raises(oidc_service.OIDCProvisionError) as exc:
        await provision_oidc_user(session, cfg=_cfg(), identity=_identity(email="Admin@Corp.Test"))
    assert exc.value.reason == "account linking required"


async def test_cross_provider_takeover_refused(session):
    okta_cfg = replace(_cfg(), key="okta", display_name="Okta")
    await provision_oidc_user(session, cfg=okta_cfg, identity=_identity())

    # Same email arriving with a different subject must not resolve to the okta account.
    with pytest.raises(oidc_service.OIDCProvisionError) as exc:
        await provision_oidc_user(session, cfg=_cfg(), identity=_identity(subject="other-sub"))
    assert exc.value.reason == "account linking required"


async def test_spoofed_issuer_from_other_provider_denied(session):
    # #226: a hostile/compromised configured provider can publish another provider's
    # issuer (Authlib only validates iss against the provider's OWN discovery metadata)
    # and mint a token carrying that trust domain's (iss, sub). The provider-scoped
    # match must refuse it — a DIFFERENT attacker email so the denial can only come from
    # the issuer-scoping fix, not the email-collision path.
    okta_cfg = replace(_cfg(), key="okta", display_name="Okta")
    victim, _ = await provision_oidc_user(
        session,
        cfg=okta_cfg,
        identity=_identity(issuer="https://okta.example/", subject="victim-sub", email="victim@corp.test"),
    )
    victim_id = victim.id
    assert victim.auth_provider == "okta"

    hostile_cfg = replace(_cfg(), key="authentik")  # a different configured provider
    with pytest.raises(oidc_service.OIDCProvisionError) as exc:
        await provision_oidc_user(
            session,
            cfg=hostile_cfg,
            identity=_identity(issuer="https://okta.example/", subject="victim-sub", email="attacker@evil.test"),
        )
    assert exc.value.reason == "identity conflict"

    # The victim account is untouched (no shadow row, no re-provision, still okta's).
    from sqlmodel import select

    rows = (await session.exec(select(User).where(User.oidc_subject == "victim-sub"))).all()
    assert [r.id for r in rows] == [victim_id]
    assert rows[0].auth_provider == "okta"
    assert rows[0].email == "victim@corp.test"


async def test_identity_keyed_on_issuer_not_adapter_key(session):
    # A colliding `sub` from a DIFFERENT issuer must NOT inherit the account — the
    # key is the validated (issuer, subject), not the admin-configurable adapter key.
    first, _ = await provision_oidc_user(
        session, cfg=_cfg(), identity=_identity(issuer="https://idp-a.test/", subject="shared-sub", email="a@sso.test")
    )
    first_id = first.id  # capture before the next commit expires the instance
    second, created = await provision_oidc_user(
        session, cfg=_cfg(), identity=_identity(issuer="https://idp-b.test/", subject="shared-sub", email="b@sso.test")
    )
    assert created is True
    assert second.id != first_id
    assert second.oidc_issuer == "https://idp-b.test/"


async def test_sso_email_unique_index_blocks_duplicate(session):
    # DB backstop for the concurrent-first-login race: two SSO rows (distinct
    # identities) can't share an email even if the app-level check is bypassed.
    from sqlalchemy.exc import IntegrityError

    session.add(
        User(
            username="dup-a",
            password_hash=None,
            email="dup@sso.test",
            auth_provider="authentik",
            oidc_issuer="https://idp.test/",
            oidc_subject="sub-a",
        )
    )
    await session.commit()
    session.add(
        User(
            username="dup-b",
            password_hash=None,
            email="dup@sso.test",
            auth_provider="okta",
            oidc_issuer="https://idp2.test/",
            oidc_subject="sub-b",
        )
    )
    with pytest.raises(IntegrityError):
        await session.commit()
    await session.rollback()


async def test_username_collision_gets_deterministic_suffix(session):
    # A local user whose USERNAME is this identity's email, but with no/other email
    # (a same-email row would be denied as a collision instead).
    session.add(User(username="new@sso.test", password_hash="x", email=None))
    await session.commit()

    user, created = await provision_oidc_user(session, cfg=_cfg(), identity=_identity())
    assert created is True
    assert user.username.startswith("new@sso.test-")
    assert len(user.username.split("-")[-1]) == 8

    # Re-login resolves by (issuer, subject), not username.
    again, created_again = await provision_oidc_user(session, cfg=_cfg(), identity=_identity())
    assert created_again is False
    assert again.id == user.id


async def test_tenant_backfill_and_conflict(session):
    entra_cfg = replace(_cfg(), key="entra", display_name="Entra")
    user, _ = await provision_oidc_user(session, cfg=entra_cfg, identity=_identity(tenant_id=None))
    assert user.auth_tenant is None

    # Lazy backfill on the first login that carries tenant provenance.
    user, _ = await provision_oidc_user(session, cfg=entra_cfg, identity=_identity(tenant_id="tenant-a"))
    assert user.auth_tenant == "tenant-a"

    # Once set, a different (or missing) tenant is an identity conflict.
    with pytest.raises(oidc_service.OIDCProvisionError):
        await provision_oidc_user(session, cfg=entra_cfg, identity=_identity(tenant_id="tenant-b"))
    with pytest.raises(oidc_service.OIDCProvisionError):
        await provision_oidc_user(session, cfg=entra_cfg, identity=_identity(tenant_id=None))


async def test_sso_account_cannot_password_login(session):
    session.add(
        User(
            username="ssoonly@sso.test",
            password_hash=None,
            email="ssoonly@sso.test",
            auth_provider="authentik",
            oidc_issuer="https://idp.test/",
            oidc_subject="sub-ssoonly",
        )
    )
    await session.commit()
    assert await verify_credentials("ssoonly@sso.test", "anything", session) is None


async def test_unverified_email_denied_on_jit(session):
    with pytest.raises(oidc_service.OIDCProvisionError) as exc:
        await provision_oidc_user(session, cfg=_cfg(), identity=_identity(email_verified=False))
    assert exc.value.reason == "email not verified"


async def test_returning_user_not_reverified(session):
    # A returning identity (matched by subject) is not re-gated on email_verified —
    # its identity is already established by (provider, subject).
    user, _ = await provision_oidc_user(session, cfg=_cfg(), identity=_identity())
    again, created = await provision_oidc_user(session, cfg=_cfg(), identity=_identity(email_verified=False))
    assert created is False
    assert again.id == user.id


async def test_returning_email_resynced_frees_stale_address(session):
    # #233: user A's IdP email changes; the returning-login sync must adopt the new
    # verified address so A's *old* address is freed for whoever gets it next —
    # otherwise B's first login is permanently denied "account linking required".
    a1, _ = await provision_oidc_user(session, cfg=_cfg(), identity=_identity(subject="sub-a", email="a@old.test"))
    a1_id = a1.id  # capture before later commits expire the instance
    assert a1.email == "a@old.test"
    a2, created = await provision_oidc_user(
        session, cfg=_cfg(), identity=_identity(subject="sub-a", email="A@New.test")
    )
    assert created is False
    assert a2.id == a1_id
    assert a2.email == "a@new.test"  # normalized + adopted

    # The old address is now free: a different identity JIT-provisions on it.
    b, created_b = await provision_oidc_user(
        session, cfg=_cfg(), identity=_identity(subject="sub-b", email="a@old.test")
    )
    assert created_b is True
    assert b.id != a1_id
    assert b.email == "a@old.test"


async def test_returning_email_sync_skips_collision(session):
    # Adopting an address already owned by another SSO account would violate
    # uq_user_sso_email — keep the stale email and let the login proceed rather than
    # 500 or silently steal the address (a real duplicate needs admin remediation).
    a, _ = await provision_oidc_user(session, cfg=_cfg(), identity=_identity(subject="sub-a", email="a@corp.test"))
    a_id = a.id  # capture before later commits expire the instance
    await provision_oidc_user(session, cfg=_cfg(), identity=_identity(subject="sub-b", email="b@corp.test"))

    a_again, created = await provision_oidc_user(
        session, cfg=_cfg(), identity=_identity(subject="sub-a", email="b@corp.test")
    )
    assert created is False
    assert a_again.id == a_id
    assert a_again.email == "a@corp.test"  # unchanged — collision was declined


async def test_returning_email_sync_ignores_unverified_claim(session):
    # An unverified email is untrustworthy (same rule as JIT) — never adopt it.
    a, _ = await provision_oidc_user(session, cfg=_cfg(), identity=_identity(subject="sub-a", email="a@old.test"))
    a_again, created = await provision_oidc_user(
        session, cfg=_cfg(), identity=_identity(subject="sub-a", email="a@new.test", email_verified=False)
    )
    assert created is False
    assert a_again.email == "a@old.test"


# --------------------------------------------------------------------------- #
# Adapters
# --------------------------------------------------------------------------- #


def test_entra_requires_tenant():
    with pytest.raises(ValueError):
        EntraAdapter().extract_identity({"iss": "https://i.test", "sub": "s", "email": "e@x.test"}, "")


def test_adapters_require_issuer():
    # (issuer, subject) is the identity key, so a missing iss must fail closed.
    with pytest.raises(ValueError, match="iss"):
        get_adapter("authentik").extract_identity({"sub": "s", "email": "e@x.test"}, "")
    with pytest.raises(ValueError, match="iss"):
        EntraAdapter().extract_identity({"sub": "s", "tid": "t", "email": "e@x.test"}, "")


def test_entra_falls_back_to_preferred_username_unverified():
    identity = EntraAdapter().extract_identity(
        {
            "iss": "https://i.test",
            "sub": "s",
            "tid": "t",
            "preferred_username": "user@corp.test",
            "email_verified": True,
        },
        "",
    )
    assert identity.email == "user@corp.test"
    # Verification claims apply to an asserted email claim, not the fallback.
    assert identity.email_verified is False
    assert identity.tenant_id == "t"
    assert identity.issuer == "https://i.test"


def test_entra_email_verified_honours_xms_edov():
    adapter = EntraAdapter()
    claims = {"iss": "https://i.test", "sub": "s", "tid": "t", "email": "e@x.test"}
    assert adapter.extract_identity({**claims, "xms_edov": True}, "").email_verified is True
    assert adapter.extract_identity({**claims, "xms_edov": False, "email_verified": True}, "").email_verified is False
    assert adapter.extract_identity({**claims, "email_verified": True}, "").email_verified is True
    assert adapter.extract_identity(claims, "").email_verified is False


def test_entra_groups_overage_denied():
    # >~200 groups: Entra omits the inline `groups` array and emits the
    # distributed-claims pointers instead. Reading that as "no groups" would
    # demote an IdP-managed admin and revoke their sessions (#227), so the
    # adapter must fail closed with a ValueError the callback turns into a
    # logged /login?error=sso.
    overage_claims = {
        "iss": "https://i.test",
        "sub": "s",
        "tid": "t",
        "email": "e@x.test",
        "email_verified": True,
        # note: no inline "groups" claim
        "_claim_names": {"groups": "src1"},
        "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/v1.0/me/getMemberObjects"}},
    }
    with pytest.raises(ValueError, match="overage"):
        EntraAdapter().extract_identity(overage_claims, "groups")


def test_entra_overage_ignored_without_role_claim():
    # A deployment that doesn't map groups to roles (role_claim="") is
    # unaffected: no group extraction is configured, so the overage pointers are
    # irrelevant and login proceeds with empty groups (no false-positive deny).
    overage_claims = {
        "iss": "https://i.test",
        "sub": "s",
        "tid": "t",
        "email": "e@x.test",
        "email_verified": True,
        "_claim_names": {"groups": "src1"},
        "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/"}},
    }
    identity = EntraAdapter().extract_identity(overage_claims, "")
    assert identity.groups == []
    assert identity.email == "e@x.test"


def test_entra_inline_groups_unaffected_by_overage_guard():
    # Happy path: an inline groups array (no overage) still extracts normally —
    # the guard only fires when the claim is displaced into _claim_names.
    identity = EntraAdapter().extract_identity(
        {
            "iss": "https://i.test",
            "sub": "s",
            "tid": "t",
            "email": "e@x.test",
            "email_verified": True,
            "groups": ["ebs-admins", "eng"],
        },
        "groups",
    )
    assert identity.groups == ["ebs-admins", "eng"]


def test_entra_roles_overage_denied():
    # emit_as_roles: group membership is emitted into the `roles` claim, but the
    # overage indicator is STILL keyed on `groups` in _claim_names. A deployment
    # with role_claim="roles" must also fail closed — otherwise the absent `roles`
    # claim reads as "no groups" and demotes the admin (the review-bot finding on
    # PR #241).
    overage_claims = {
        "iss": "https://i.test",
        "sub": "s",
        "tid": "t",
        "email": "e@x.test",
        "email_verified": True,
        # no inline "roles" claim; overage pointer keyed on "groups"
        "_claim_names": {"groups": "src1"},
        "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/v1.0/me/getMemberObjects"}},
    }
    with pytest.raises(ValueError, match="overage"):
        EntraAdapter().extract_identity(overage_claims, "roles")


def test_entra_inline_roles_not_overaged():
    # No false-positive deny: when the configured role_claim IS delivered inline
    # (e.g. genuine app roles), an unrelated `_claim_names.groups` pointer must not
    # trip the guard — the present role source is trusted.
    identity = EntraAdapter().extract_identity(
        {
            "iss": "https://i.test",
            "sub": "s",
            "tid": "t",
            "email": "e@x.test",
            "email_verified": True,
            "roles": ["ebs-admins"],
            "_claim_names": {"groups": "src1"},
            "_claim_sources": {"src1": {"endpoint": "https://graph.microsoft.com/"}},
        },
        "roles",
    )
    assert identity.groups == ["ebs-admins"]


@pytest.mark.parametrize("key", ["authentik", "auth0", "okta"])
def test_standard_adapters_share_claim_mapping(key):
    adapter = get_adapter(key)
    identity = adapter.extract_identity(
        {
            "iss": "https://i.test",
            "sub": "s",
            "email": "e@x.test",
            "email_verified": True,
            "name": "N",
            "groups": ["g1", "g2"],
        },
        "groups",
    )
    assert identity.issuer == "https://i.test"
    assert identity.subject == "s"
    assert identity.email == "e@x.test"
    assert identity.email_verified is True
    assert identity.display_name == "N"
    assert identity.groups == ["g1", "g2"]


def test_standard_adapter_missing_email_raises():
    with pytest.raises(ValueError):
        get_adapter("authentik").extract_identity({"iss": "https://i.test", "sub": "s"}, "")


def test_group_claim_shapes():
    adapter = get_adapter("authentik")
    base = {"iss": "https://i.test", "sub": "s", "email": "e@x.test"}
    assert adapter.extract_identity({**base, "groups": "solo"}, "groups").groups == ["solo"]
    assert adapter.extract_identity(base, "groups").groups == []
    assert adapter.extract_identity({**base, "groups": ["a"]}, "").groups == []


# --------------------------------------------------------------------------- #
# Config / validation
# --------------------------------------------------------------------------- #


def test_env_config_builds_authentik_metadata_url():
    providers = env_config().enabled_providers()
    assert [p.key for p in providers] == ["authentik"]
    assert providers[0].metadata_url == (
        "https://authentik.test/application/o/iceberg-ebs/.well-known/openid-configuration"
    )


def test_config_builds_okta_and_auth0_metadata_urls():
    cfg = replace(
        env_config(),
        oidc_auth0_enabled=True,
        oidc_auth0_client_id="c",
        oidc_auth0_domain="tenant.eu.auth0.com",
        oidc_okta_enabled=True,
        oidc_okta_client_id="c",
        oidc_okta_domain="org.okta.com",
        oidc_okta_auth_server="default",
    )
    by_key = {p.key: p for p in cfg.enabled_providers()}
    assert by_key["auth0"].metadata_url == "https://tenant.eu.auth0.com/.well-known/openid-configuration"
    assert by_key["okta"].metadata_url == "https://org.okta.com/oauth2/default/.well-known/openid-configuration"
    # Org authorization server: no /oauth2/ path segment.
    org = replace(cfg, oidc_okta_auth_server="")
    assert {p.key: p for p in org.enabled_providers()}["okta"].metadata_url == (
        "https://org.okta.com/.well-known/openid-configuration"
    )


def test_auth_mode_local_disables_providers():
    cfg = replace(env_config(), auth_mode="local")
    assert cfg.enabled_providers() == []


@pytest.mark.parametrize(
    "changes, message_part",
    [
        ({"auth_mode": "jwt"}, "Authentication mode"),
        ({"oidc_redirect_base_url": "not-a-url"}, "absolute http"),
        ({"oidc_authentik_role_map": "group=analyst"}, "role map"),
        ({"oidc_authentik_role_map": "junkpair"}, "role map"),
        ({"oidc_authentik_app_slug": ""}, "incomplete"),
        ({"oidc_authentik_scopes": "email profile"}, "openid"),
        # Shape validation must live in validate_config (the env-seed/startup path),
        # not only in the PUT route — a scheme-less authentik base URL or a
        # URL-shaped auth0/okta domain would otherwise build a garbage metadata URL.
        ({"oidc_authentik_base_url": "authentik.internal"}, "authentik base URL"),
    ],
)
def test_validate_config_rejects(changes, message_part):
    with pytest.raises(ValueError, match=message_part):
        validate_config(replace(env_config(), **changes))


def test_validate_config_rejects_url_shaped_domain(monkeypatch):
    from pydantic import SecretStr

    monkeypatch.setattr(settings, "oidc_auth0_client_secret", SecretStr("s"))
    cfg = replace(
        env_config(),
        oidc_auth0_enabled=True,
        oidc_auth0_client_id="c",
        oidc_auth0_domain="https://tenant.eu.auth0.com",  # scheme pasted in by mistake
    )
    with pytest.raises(ValueError, match="auth0 domain must be a bare hostname"):
        validate_config(cfg)


def test_validate_config_requires_env_secret(monkeypatch):
    from pydantic import SecretStr

    monkeypatch.setattr(settings, "oidc_authentik_client_secret", SecretStr(""))
    with pytest.raises(ValueError, match="CLIENT_SECRET"):
        validate_config(env_config())


def test_validate_config_lockout_guard():
    # OIDC-only mode with no complete enabled provider would leave no login path.
    with pytest.raises(ValueError, match="OIDC-only"):
        validate_config(replace(env_config(), auth_mode="oidc", oidc_authentik_enabled=False))
    # With the complete conftest-enabled provider it is accepted.
    validate_config(replace(env_config(), auth_mode="oidc"))


def test_validate_config_rejects_multitenant_entra_alias(monkeypatch):
    from pydantic import SecretStr

    monkeypatch.setattr(settings, "oidc_entra_client_secret", SecretStr("s"))
    cfg = replace(
        env_config(),
        oidc_entra_enabled=True,
        oidc_entra_client_id="c",
        oidc_entra_tenant_id="common",
    )
    with pytest.raises(ValueError, match="specific tenant"):
        validate_config(cfg)


# --------------------------------------------------------------------------- #
# Transport plumbing
# --------------------------------------------------------------------------- #


async def test_non_closing_transport_shields_inner():
    class _Recorder(httpx.AsyncBaseTransport):
        def __init__(self):
            self.closed = False
            self.requests = []

        async def handle_async_request(self, request):
            self.requests.append(request)
            return httpx.Response(204)

        async def aclose(self):
            self.closed = True

    inner = _Recorder()
    wrapper = _NonClosingTransport(inner)
    # Authlib closes its throwaway client (and thus the transport) after every
    # call; the wrapper must absorb that so the shared chain survives call #2.
    await wrapper.aclose()
    assert inner.closed is False
    request = httpx.Request("GET", "https://idp.test/.well-known/openid-configuration")
    response = await wrapper.handle_async_request(request)
    assert response.status_code == 204
    assert inner.requests == [request]


def test_registration_uses_shared_transport_and_pkce(patch_oidc):
    # ensure_registered ran inside patch_oidc; inspect the registered kwargs via a
    # fresh registration pass on a clean OAuth object.
    oidc_service.reset_registration()
    configs = oidc_service.register_providers()
    assert [c.key for c in configs] == ["authentik"]
    registered = oidc_service.oauth._registry["authentik"][1]
    client_kwargs = registered["client_kwargs"]
    assert client_kwargs["code_challenge_method"] == "S256"
    assert isinstance(client_kwargs["transport"], _NonClosingTransport)


# --------------------------------------------------------------------------- #
# Routes (full HTTP flow, Authlib stubbed)
# --------------------------------------------------------------------------- #


async def test_login_redirects_to_idp(anon_client, patch_oidc):
    patch_oidc(_FakeOIDCClient())
    r = await anon_client.get("/auth/oidc/authentik/login")
    assert r.status_code in (302, 307)
    assert r.headers["location"].startswith("https://authentik.test/authorize")


async def test_login_unknown_provider_404(anon_client):
    r = await anon_client.get("/auth/oidc/nonesuch/login")
    assert r.status_code == 404


async def test_callback_provisions_and_starts_session(anon_client, patch_oidc):
    patch_oidc(_FakeOIDCClient(claims=_claims()))
    r = await anon_client.get("/auth/oidc/authentik/callback?code=x&state=y")
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert settings.session_cookie_name in r.cookies

    # The minted cookie is a real session: the dashboard renders.
    dash = await anon_client.get("/", cookies={settings.session_cookie_name: r.cookies[settings.session_cookie_name]})
    assert dash.status_code == 200


async def test_callback_second_login_reuses_account(anon_client, patch_oidc, session):
    from sqlmodel import select

    patch_oidc(_FakeOIDCClient(claims=_claims()))
    first = await anon_client.get("/auth/oidc/authentik/callback?code=x&state=y")
    second = await anon_client.get("/auth/oidc/authentik/callback?code=x2&state=y2")
    assert first.status_code == second.status_code == 303
    users = (await session.exec(select(User).where(User.email == "route@sso.test"))).all()
    assert len(users) == 1


async def test_callback_invalid_token_denies(anon_client, patch_oidc, caplog):
    patch_oidc(_FakeOIDCClient(error=OAuthError(error="mismatching_state")))
    secret_code = "super-secret-authorization-code"
    r = await anon_client.get(f"/auth/oidc/authentik/callback?code={secret_code}&state=y")
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso"
    # The authorization code must never reach the app's logs (the httpx *test
    # client* logs its own request line, so scope the check to app loggers).
    app_logs = " ".join(rec.getMessage() for rec in caplog.records if rec.name.startswith("app."))
    assert "id-token validation" in app_logs
    assert secret_code not in app_logs


async def test_callback_missing_validated_claims_denies(anon_client, patch_oidc):
    # token["userinfo"] is None → Authlib could not ID-token-validate; the route
    # must fail closed, NOT fall back to the userinfo endpoint (auth downgrade).
    patch_oidc(_FakeOIDCClient(claims=None))
    r = await anon_client.get("/auth/oidc/authentik/callback?code=x&state=y")
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso"


async def test_callback_network_error_redirects_not_500(anon_client, patch_oidc):
    # The IdP/proxy is unreachable during the token exchange — httpx raises (not
    # OAuthError). The user must land on /login?error=sso, never a raw 500.
    patch_oidc(_FakeOIDCClient(error=httpx.ConnectError("token endpoint unreachable")))
    r = await anon_client.get("/auth/oidc/authentik/callback?code=x&state=y")
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso"


async def test_login_start_network_error_redirects_not_500(anon_client, patch_oidc):
    patch_oidc(_FakeOIDCClient(redirect_error=httpx.ConnectError("discovery unreachable")))
    r = await anon_client.get("/auth/oidc/authentik/login")
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso"


async def test_callback_email_collision_denies(anon_client, patch_oidc, session):
    session.add(User(username="victim", password_hash="x", email="route@sso.test", is_admin=True))
    await session.commit()
    patch_oidc(_FakeOIDCClient(claims=_claims()))
    r = await anon_client.get("/auth/oidc/authentik/callback?code=x&state=y")
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=sso"
    assert settings.session_cookie_name not in r.cookies


async def test_login_page_shows_sso_button(anon_client):
    r = await anon_client.get("/login")
    assert r.status_code == 200
    assert "Continue with Authentik" in r.text
    assert 'action="/login"' in r.text  # local form still present in "both" mode


async def test_auth_mode_oidc_disables_local_login(anon_client):
    oidc_settings.set_config(replace(env_config(), auth_mode="oidc"))
    oidc_service.reset_registration()

    page = await anon_client.get("/login")
    assert 'action="/login"' not in page.text
    assert "Continue with Authentik" in page.text

    r = await anon_client.post("/login", data={"username": "testadmin", "password": "testpass"})
    assert r.status_code == 403
    assert "Local sign-in is disabled" in r.text


async def test_auth_mode_local_hides_sso(anon_client):
    oidc_settings.set_config(replace(env_config(), auth_mode="local"))
    oidc_service.reset_registration()

    page = await anon_client.get("/login")
    assert "Continue with Authentik" not in page.text
    assert 'action="/login"' in page.text

    r = await anon_client.get("/auth/oidc/authentik/login")
    assert r.status_code == 404


async def test_change_password_rejected_for_sso_account(anon_client, session):
    session.add(User(username="sso@sso.test", password_hash=None, email="sso@sso.test"))
    await session.commit()
    cookie = create_session_cookie("sso@sso.test")
    r = await anon_client.request(
        "PATCH",
        "/api/users/me/password",
        json={"current_password": "irrelevant-1", "new_password": "irrelevant-2"},
        cookies={settings.session_cookie_name: cookie},
    )
    assert r.status_code == 400
    assert "SSO" in r.json()["detail"]


async def test_oidc_login_start_covered_by_login_rate_limit(anon_client, monkeypatch):
    from app.ratelimit import login_request_limiter

    monkeypatch.setattr(settings, "login_rate_limit_enabled", True)
    monkeypatch.setattr(login_request_limiter, "check", lambda ip: 30)
    r = await anon_client.get("/auth/oidc/authentik/login")
    assert r.status_code == 429
    assert r.headers["Retry-After"] == "30"


async def test_oidc_callback_not_rate_limited(anon_client, patch_oidc, monkeypatch):
    # The callback must NEVER be throttled: a 429 there burns the single-use
    # authorization code mid-flow. Even with the limiter tripped, the callback runs.
    from app.ratelimit import login_request_limiter

    monkeypatch.setattr(settings, "login_rate_limit_enabled", True)
    monkeypatch.setattr(login_request_limiter, "check", lambda ip: 30)
    patch_oidc(_FakeOIDCClient(claims=_claims()))
    r = await anon_client.get("/auth/oidc/authentik/callback?code=x&state=y")
    assert r.status_code == 303
    assert r.headers["location"] == "/"  # provisioned + signed in, not 429
