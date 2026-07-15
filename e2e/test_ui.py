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


def _assert_no_critical_errors(collect_errors):
    console_errors, page_errors = collect_errors
    # A CSP violation surfaces as a "Refused to …" console error — the hash-drift check.
    csp = [e for e in console_errors if "Refused to" in e or "Content Security Policy" in e]
    assert not csp, f"CSP violations in console: {csp}"
    # An uncaught JS exception means a component (e.g. Alpine) failed to initialise.
    assert not page_errors, f"uncaught page errors: {page_errors}"


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
