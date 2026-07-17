"""Admin SSO/OIDC settings API tests (#32).

Client secrets must never appear in any response; the PUT surface is a strict
whitelist validated against the RESULTING config (lockout prevention).
"""

from app import oidc_settings
from app.oidc import service as oidc_service


async def test_settings_require_admin(anon_client):
    r = await anon_client.get("/api/oidc/settings")
    assert r.status_code == 401


async def test_get_settings_seeds_from_env_and_hides_secrets(client):
    r = await client.get("/api/oidc/settings")
    assert r.status_code == 200
    body = r.json()
    # Seeded from the conftest env: authentik enabled, mode "both".
    assert body["settings"]["auth_mode"] == "both"
    assert body["settings"]["oidc_authentik_enabled"] is True
    assert body["settings"]["oidc_authentik_base_url"] == "https://authentik.test"
    # Secret status is booleans only; the value never appears anywhere.
    assert body["client_secrets_set"] == {"entra": False, "authentik": True, "auth0": False, "okta": False}
    assert "test-client-secret" not in r.text
    assert not any("client_secret" in k for k in body["settings"])


async def test_put_rejects_secret_keys(client):
    r = await client.put("/api/oidc/settings", json={"oidc_authentik_client_secret": "sneaky"})
    assert r.status_code == 422


async def test_put_rejects_bad_role_map_value(client):
    r = await client.put("/api/oidc/settings", json={"oidc_authentik_role_map": "group=analyst"})
    assert r.status_code == 422
    assert "role map" in r.json()["detail"]


async def test_put_rejects_scopes_without_openid(client):
    r = await client.put("/api/oidc/settings", json={"oidc_authentik_scopes": "email profile"})
    assert r.status_code == 422
    assert "openid" in r.json()["detail"]


async def test_put_rejects_lockout(client):
    # OIDC-only mode while disabling the only complete provider = no login path.
    r = await client.put("/api/oidc/settings", json={"auth_mode": "oidc", "oidc_authentik_enabled": False})
    assert r.status_code == 422
    assert "OIDC-only" in r.json()["detail"]


async def test_put_rejects_enabling_provider_without_env_secret(client):
    r = await client.put(
        "/api/oidc/settings",
        json={"oidc_okta_enabled": True, "oidc_okta_client_id": "c", "oidc_okta_domain": "org.okta.com"},
    )
    assert r.status_code == 422
    assert "OKTA_CLIENT_SECRET" in r.json()["detail"]


async def test_put_normalizes_and_persists(client):
    r = await client.put(
        "/api/oidc/settings",
        json={"auth_mode": "BOTH", "oidc_redirect_base_url": "https://ebs.example.com/"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["settings"]["auth_mode"] == "both"
    assert body["settings"]["oidc_redirect_base_url"] == "https://ebs.example.com"

    again = await client.get("/api/oidc/settings")
    assert again.json()["settings"]["oidc_redirect_base_url"] == "https://ebs.example.com"


async def test_put_rejects_domain_with_scheme(client):
    r = await client.put("/api/oidc/settings", json={"oidc_okta_domain": "https://org.okta.com"})
    assert r.status_code == 422


async def test_put_resets_authlib_registration(client):
    oidc_service.ensure_registered()
    before = oidc_service.oauth
    r = await client.put("/api/oidc/settings", json={"oidc_authentik_role_map": "ebs-admins=admin"})
    assert r.status_code == 200
    # A fresh OAuth object proves the cached Authlib clients were discarded —
    # re-register() alone would keep serving the stale cached client.
    assert oidc_service.oauth is not before
    # The refreshed snapshot carries the change without a restart.
    assert oidc_settings.get_config().oidc_authentik_role_map == "ebs-admins=admin"


async def test_admin_oidc_page_renders(client):
    r = await client.get("/admin/oidc")
    assert r.status_code == 200
    assert "Single sign-on" in r.text
    assert "test-client-secret" not in r.text
