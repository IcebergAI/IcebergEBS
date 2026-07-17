"""Capture the README screenshots from a running, seeded IcebergEBS instance.

Drives the UI with Playwright/Chromium and writes PNGs into docs/screenshots/.
Run scripts/seed_demo.py first so the pages have data on them.

Playwright is deliberately NOT in uv.lock (see the e2e suite) — install it into a
throwaway venv:

    python -m venv /tmp/pw-venv && /tmp/pw-venv/bin/pip install playwright
    /tmp/pw-venv/bin/playwright install chromium   # no-op if already cached

    ICEBERG_EBS_ADMIN_USERNAME=admin ICEBERG_EBS_ADMIN_PASSWORD=... \
        /tmp/pw-venv/bin/python scripts/capture_screenshots.py \
        [--base-url http://localhost:8000] [--out docs/screenshots]

Drive the dev app directly on :8000, not the Caddy edge — see
.claude/rules/frontend.md (proxy-headers/Origin mismatch 403s the login POST).
"""

import argparse
import os
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

VIEWPORT = {"width": 1440, "height": 900}


def login(page: Page, base_url: str, username: str, password: str) -> None:
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{base_url}/")


def top_risk_extension_id(page: Page, base_url: str) -> int | None:
    """Highest-scored extension — the most interesting detail page to show."""
    resp = page.context.request.get(
        f"{base_url}/api/extensions", params={"sort": "risk_score", "order": "desc", "limit": 1}
    )
    items = resp.json().get("items", [])
    return items[0]["id"] if items else None


def shot(page: Page, url: str, path: Path) -> None:
    page.goto(url)
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(path))
    print(f"  wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--out", default="docs/screenshots")
    args = parser.parse_args()

    username = os.environ.get("ICEBERG_EBS_ADMIN_USERNAME", "admin")
    password = os.environ.get("ICEBERG_EBS_ADMIN_PASSWORD", "admin")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for theme in ("light", "dark"):
            context = browser.new_context(viewport=VIEWPORT, device_scale_factor=2)
            # theme-boot.js resolves the picker preference from localStorage before
            # first paint; pin it so the capture doesn't follow the host's OS theme.
            context.add_init_script(f"try {{ localStorage.setItem('icebergebs-theme', '{theme}'); }} catch (e) {{}}")
            page = context.new_page()
            login(page, args.base_url, username, password)

            if theme == "dark":
                # Dark run: dashboard only — a taste of the theme, not a full duplicate set.
                shot(page, f"{args.base_url}/", out / "dashboard-dark.png")
                context.close()
                continue

            shot(page, f"{args.base_url}/", out / "dashboard.png")
            ext_id = top_risk_extension_id(page, args.base_url)
            if ext_id is None:
                sys.exit("no extensions found — run scripts/seed_demo.py first")
            shot(page, f"{args.base_url}/extensions/{ext_id}", out / "extension-detail.png")
            shot(page, f"{args.base_url}/extensions/add", out / "add-extension.png")
            shot(page, f"{args.base_url}/account", out / "alerts-webhooks.png")
            context.close()
        browser.close()
    print("done")


if __name__ == "__main__":
    main()
