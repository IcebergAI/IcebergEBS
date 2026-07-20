"""Regenerate the documentation screenshots against the running dev app.

Matches the existing set: 1440x900 viewport at deviceScaleFactor 2 => 2880x1800.
Writes to docs/screenshots/ (the canonical home) and copies into
website/docs/assets/ (per CLAUDE.md, the site's copies).
"""

import os
import shutil
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
# Derived from this file's location, never hard-coded: the script writes PNGs, so a
# stale absolute path would silently write outside the checkout it was run from.
REPO = Path(__file__).resolve().parents[2]
CANON = REPO / "docs" / "screenshots"
SITE = REPO / "website" / "docs" / "assets"

for _d in (CANON, SITE):
    if not _d.is_dir():
        raise SystemExit(f"expected {_d} to exist — is {REPO} the repository root?")

errors = []


def shoot(page, path, name):
    page.goto(f"{BASE}{path}")
    page.wait_for_load_state("networkidle")
    page.wait_for_function("() => typeof window.Alpine !== 'undefined'")
    page.wait_for_timeout(900)  # let Alpine paint + the trend chart draw
    out = CANON / f"{name}.png"
    page.screenshot(path=str(out))
    shutil.copyfile(out, SITE / f"{name}.png")
    print(f"  {name}.png")


with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
    page = ctx.new_page()
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', os.environ["ICEBERG_EBS_ADMIN_USERNAME"])
    page.fill('input[name="password"]', os.environ["ICEBERG_EBS_ADMIN_PASSWORD"])
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/")

    print("light theme:")
    shoot(page, "/", "dashboard")

    # The detail shot is React Developer Tools, as before.
    page.goto(f"{BASE}/?q=React%20Developer%20Tools")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(600)
    page.locator("table tbody tr").first.click()
    page.wait_for_url("**/extensions/**")
    detail_url = page.url.replace(BASE, "")
    shoot(page, detail_url, "extension-detail")

    shoot(page, "/account", "alerts-webhooks")
    shoot(page, "/extensions/add", "add-extension")

    # Dark theme via the rail user menu, then re-shoot the dashboard.
    print("dark theme:")
    page.goto(f"{BASE}/")
    page.wait_for_function("() => typeof window.Alpine !== 'undefined'")
    page.click("aside.rail .rail-id-btn")
    page.click("button:has-text('Dark')")
    page.wait_for_timeout(500)
    assert page.get_attribute("html", "data-theme") == "dark", "theme did not switch"
    shoot(page, "/", "dashboard-dark")

    # Leave the profile back on light so a later run starts clean.
    page.click("aside.rail .rail-id-btn")
    page.click("button:has-text('Light')")
    page.wait_for_timeout(300)

    b.close()

real = [e for e in errors if "favicon" not in e.lower()]
print(f"\nconsole/page errors: {len(real)}")
for e in real[:10]:
    print("   !", e)
sys.exit(1 if real else 0)
