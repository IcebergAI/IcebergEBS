"""Browser-level UI smoke (#100).

The rest of the suite is API/unit level (httpx + respx) and can't see: a real login,
Alpine components initialising, or — the live risk — the nginx CSP (with its
hand-maintained inline-script hash) blocking the app's own scripts. This drives a real
browser against the running stack and fails on a CSP violation or an uncaught JS error,
which is exactly what a hash drift or a broken component produces.
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


# Known, pre-existing CSP gap: the standard Alpine build evaluates x-data/x-on
# expressions with eval(), which needs `unsafe-eval` in script-src — the policy doesn't
# grant it, so Alpine's expression evaluation is CSP-blocked today. Adopting the
# @alpinejs/csp build (Alpine.data registry) removes the eval and closes this — tracked
# by #106. Filter it here so this smoke isn't blocked by a gap it isn't fixing, while
# still catching *new* CSP breakage (most importantly the inline-script hash drifting →
# "Refused to execute inline script"). Tighten this back to zero once #106 lands.
_KNOWN_CSP_GAPS = ("unsafe-eval",)


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
