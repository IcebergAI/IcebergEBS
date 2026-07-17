"""Browser-level UI smoke (#100).

The rest of the suite is API/unit level (httpx + respx) and can't see: a real login,
Alpine components initialising, or — the live risk — the Caddy CSP blocking the app's
own scripts. This drives a real browser against the running stack and fails on ANY CSP
violation or uncaught JS error: since #106 the policy is a strict script-src 'self'
(no inline scripts, @alpinejs/csp build) and there are no tolerated gaps.
"""

import os

import pytest
from playwright.sync_api import Page, expect

BASE_URL = os.environ.get("BASE_URL", "https://localhost").rstrip("/")
ADMIN_USER = os.environ.get("ICEBERG_EBS_ADMIN_USERNAME", "admin")
ADMIN_PASS = os.environ.get("ICEBERG_EBS_ADMIN_PASSWORD", "")


@pytest.fixture
def collect_errors(page: Page):
    """Record console errors + uncaught page exceptions from before the first navigation."""
    console_errors: list[str] = []
    page_errors: list[str] = []
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
    return console_errors, page_errors


# #106 landed: the @alpinejs/csp build + Alpine.data registry removed the eval
# dependency, so there are no tolerated CSP gaps — any violation fails the smoke.
_KNOWN_CSP_GAPS: tuple[str, ...] = ()


def _unexpected(errors):
    return [e for e in errors if not any(gap in e for gap in _KNOWN_CSP_GAPS)]


def _assert_no_critical_errors(collect_errors):
    console_errors, page_errors = collect_errors
    # A CSP violation surfaces as a "Refused to …" console error — the hash-drift check.
    csp = [e for e in _unexpected(console_errors) if "Refused to" in e or "Content Security Policy" in e]
    assert not csp, f"unexpected CSP violations in console: {csp}"
    # An uncaught JS exception means a component failed (beyond the known Alpine-eval gap).
    assert not _unexpected(page_errors), f"unexpected page errors: {_unexpected(page_errors)}"


def _login(page: Page):
    page.goto(f"{BASE_URL}/login")
    page.fill("input[name=username]", ADMIN_USER)
    page.fill("input[name=password]", ADMIN_PASS)
    page.click("button[type=submit]")
    page.wait_for_url(f"{BASE_URL}/")


def test_login_and_dashboard_render(page: Page, collect_errors):
    _login(page)
    # The dashboard shell rendered (a known stat tile), proving auth + template + assets.
    expect(page.locator("text=Fetch health").first).to_be_visible()
    # House shell present (#105): the brand strip and the dark rail.
    expect(page.locator(".brandbar")).to_be_visible()
    expect(page.locator("aside.rail")).to_be_visible()
    # Alpine must actually load — the interactive controls depend on it, and a plain
    # resource error from a broken vendored script would otherwise slip past the error
    # filters. Since #106 (CSP build + registry) expressions evaluate for real, so the
    # user-menu dropdown must be x-cloak-hidden until clicked — proof components
    # initialised, not merely that the library loaded.
    page.wait_for_function("() => typeof window.Alpine !== 'undefined'")
    expect(page.locator("text=Sign out")).not_to_be_visible()
    _assert_no_critical_errors(collect_errors)


def test_topbar_search_interaction(page: Page, collect_errors):
    _login(page)
    # The '/' shortcut focuses the topbar search (static/js/topbar-search.js); Enter
    # navigates to the filtered dashboard — a real client-side interaction.
    page.keyboard.press("/")
    search = page.locator(".search input")
    expect(search).to_be_focused()
    search.fill("example")
    search.press("Enter")
    page.wait_for_url(f"{BASE_URL}/?q=example")
    _assert_no_critical_errors(collect_errors)


def test_theme_picker_roundtrip(page: Page, collect_errors):
    """The system/light/dark picker (#106): drives the Alpine userMenu component —
    the first CI proof that Alpine interactivity actually works behind the strict
    CSP — and theme-boot.js's persistence across a reload. The menu lives at the
    bottom of the rail (the account/settings dropdown), not the topbar."""
    _login(page)
    # Open the rail account menu (Alpine @click) and pick the dark theme.
    page.click("aside.rail .rail-id-btn")
    page.click("button:has-text('Dark')")
    assert page.get_attribute("html", "data-theme") == "dark"
    # The choice survives a reload via localStorage + the ebs_* cookies, stamped
    # before first paint by the external theme-boot.js.
    page.reload()
    assert page.get_attribute("html", "data-theme") == "dark"
    page.click("aside.rail .rail-id-btn")
    page.click("button:has-text('System')")
    _assert_no_critical_errors(collect_errors)


def test_slash_shortcut_does_not_hijack_text_fields(page: Page, collect_errors):
    """Regression: the '/' topbar-search shortcut (static/js/topbar-search.js) must
    not steal focus while the user is typing into a field. Webhook URLs, extension
    IDs and bulk lists are full of slashes, so hijacking focus on '/' swallowed the
    character — a webhook URL typed as 'https://hooks…' only ever captured 'https:'."""
    _login(page)
    page.goto(f"{BASE_URL}/account")
    page.click("text=New destination")
    url = page.locator("input[placeholder^='https://hooks']")
    url.click()
    typed = "https://hooks.example.com/services/T00/B00/xyz"
    page.keyboard.type(typed)
    # The whole slash-bearing value lands in the field, and focus never jumped away.
    expect(url).to_have_value(typed)
    expect(url).to_be_focused()
    # And the shortcut still works when NOT in a field: '/' focuses the search box.
    page.locator("h1").first.click()
    page.keyboard.press("/")
    expect(page.locator(".search input")).to_be_focused()
    _assert_no_critical_errors(collect_errors)
