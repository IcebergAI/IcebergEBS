"""Seed a realistic demo dataset for the documentation screenshots.

Values mirror the existing docs/screenshots set so the refreshed shots read as the
same workspace, just on the current UI. Everything is synthetic: no store is
contacted, and the cached install_footprint is backed by real InstallObservation
rows so the dashboard's Top-exposure ranking is internally consistent rather than
a fabricated number.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, tuple_
from sqlalchemy.engine import make_url
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.auth import hash_password
from app.config import settings
from app.database import engine
from app.inspector import PackageAnalysis, PackageFinding
from app.models import (
    AlertDestination,
    AlertRule,
    Extension,
    FetchLog,
    InstallObservation,
    User,
)

NOW = datetime.now(timezone.utc)

# name, store, publisher, ext_id, version, risk, installs, footprint, updated_days_ago
EXTS = [
    (
        "React Developer Tools",
        "chrome",
        "Meta Platforms, INC.",
        "fmkadmapgofadopljbjfkapdkoienihi",
        "7.0.1",
        54,
        5_000_000,
        3,
        271,
    ),
    (
        "PayPal Honey: Automated Coupons & Rewards",
        "chrome",
        "PayPal Inc.",
        "bmnlcjabgnpnenekpadlanbbkooimhnj",
        "16.2.1",
        50,
        12_000_000,
        2,
        44,
    ),
    (
        "Session Buddy - Tab & Bookmark Manager",
        "chrome",
        "Session Buddy",
        "edacconmaakjimmfgnblocblbcdcpbko",
        "4.1.2",
        43,
        900_000,
        4,
        83,
    ),
    ("Dark Reader", "chrome", "Dark Reader Ltd", "eimadpbcbfnmbkopoojfekhnkhdbieeh", "4.9.108", 42, 6_000_000, 3, 4),
    (
        "Adblock Plus - free ad blocker",
        "edge",
        "eyeo GmbH",
        "gmgoamodcdcjnbaobigkjelfplakmdhh",
        "3.25.0",
        34,
        5_000_000,
        5,
        31,
    ),
    (
        "Microsoft Editor: Spelling & Grammar",
        "edge",
        "Microsoft",
        "hokifickgkhplphjiodbggjmoafhignh",
        "2.1.0",
        22,
        3_000_000,
        5,
        61,
    ),
    ("ESLint", "vscode", "Microsoft", "dbaeumer.vscode-eslint", "3.0.10", 20, 30_000_000, 9, 12),
    ("Prettier - Code formatter", "vscode", "Prettier", "esbenp.prettier-vscode", "11.0.0", 18, 40_000_000, 10, 26),
    ("GitHub Copilot", "vscode", "GitHub", "github.copilot", "1.250.0", 16, 25_000_000, 12, 6),
    (
        "Grammarly: AI Writing Assistant and Grammar Checker App",
        "chrome",
        "Grammarly Inc.",
        "kbfnbcaeplbcioakkpcpgfkobkghlhen",
        "14.1180.0",
        12,
        10_000_000,
        32,
        9,
    ),
    (
        "LastPass: Free Password Manager",
        "chrome",
        "LastPass",
        "hdokiejnpimakedhajhdlcegeplioahd",
        "4.135.0",
        12,
        8_000_000,
        22,
        18,
    ),
    ("Python", "vscode", "Microsoft", "ms-python.python", "2026.6.0", 12, 150_000_000, 18, 8),
    ("uBlock Origin", "chrome", "Raymond Hill", "cjpalhdlnbpafiamejdnhcphjbkeiagm", "1.68.0", 12, 10_000_000, 17, 22),
]

DEPARTMENTS = ["Engineering", "Sales", "Marketing", "Finance", "Support"]

STORE_URL = {
    "chrome": "https://chromewebstore.google.com/detail/{id}",
    "edge": "https://microsoftedge.microsoft.com/addons/detail/{id}",
    "vscode": "https://marketplace.visualstudio.com/items?itemName={id}",
}

DESCRIPTIONS = {
    "React Developer Tools": "Adds React debugging tools to the Chrome Developer Tools. Created from revision 3cde211b0c on 10/20/2025.",
    "Grammarly: AI Writing Assistant and Grammar Checker App": "Improve your writing with Grammarly's AI writing assistant — grammar, spelling, tone, and clarity suggestions wherever you type.",
    "LastPass: Free Password Manager": "LastPass remembers your passwords so that you can focus on the more important things in life.",
    "Dark Reader": "Dark mode for every website. Take care of your eyes, use dark theme for night and daily browsing.",
    "uBlock Origin": "Finally, an efficient wide-spectrum content blocker. Easy on CPU and memory.",
    "Python": "Python language support with extension access points for IntelliSense, debugging, formatting, linting, and more.",
    "GitHub Copilot": "Your AI pair programmer — get inline code suggestions as you type.",
}

# Matches the score breakdown shown in the existing extension-detail screenshot.
REACT_DETAIL = {
    "permissions": 25,
    "popularity": 0,
    "publisher": 0,
    "staleness": 4,
    "code_behaviour": 15,
    "external_domains": 10,
    "total": 54,
}


def detail_for(risk: int) -> dict:
    """A plausible per-signal split that sums to the total."""
    perms = min(25, round(risk * 0.42))
    code = min(15, round(risk * 0.24))
    dom = min(10, round(risk * 0.16))
    stale = min(15, round(risk * 0.10))
    pub = min(15, max(0, risk - perms - code - dom - stale))
    pop = max(0, risk - perms - code - dom - stale - pub)
    return {
        "permissions": perms,
        "popularity": pop,
        "publisher": pub,
        "staleness": stale,
        "code_behaviour": code,
        "external_domains": dom,
        "total": risk,
    }


REACT_DOMAINS = [
    "api.github.com",
    "cdn.jsdelivr.net",
    "fb.me",
    "github.com",
    "npmjs.com",
    "reactjs.org",
    "registry.npmjs.org",
    "unpkg.com",
    "www.npmjs.com",
    "yarnpkg.com",
]

REACT_FINDINGS = [
    (
        "critical",
        "eval-usage",
        "Dynamic code execution via eval()",
        "build/backend.js:1",
        "eval( is called on a runtime-built string",
    ),
    (
        "high",
        "remote-code",
        "Remote script loaded at runtime",
        "build/main.js:212",
        "Injects a <script> whose src is built from a variable",
    ),
    (
        "high",
        "obfuscation",
        "Heavily minified/obfuscated bundle",
        "build/backend.js",
        "Average line length 1,842 chars",
    ),
    (
        "medium",
        "network-callout",
        "Network callout to an external host",
        "build/main.js:88",
        "fetch('https://api.github.com/…')",
    ),
    (
        "medium",
        "network-callout",
        "Network callout to an external host",
        "build/main.js:141",
        "fetch('https://registry.npmjs.org/…')",
    ),
    ("medium", "storage-access", "Reads extension storage", "build/panel.js:22", "chrome.storage.local.get"),
    ("low", "inline-style", "Inline style injection", "build/panel.js:310", "element.style.cssText assignment"),
    (
        "low",
        "console-logging",
        "Verbose console logging in production build",
        "build/main.js:9",
        "console.debug retained",
    ),
]


def react_analysis() -> str:
    pa = PackageAnalysis(
        permissions=["debugger", "storage", "scripting", "tabs"],
        host_permissions=["<all_urls>"],
        external_domains=REACT_DOMAINS,
        external_urls=[f"https://{d}/" for d in REACT_DOMAINS[:4]],
        network_callout_urls=["https://api.github.com/repos", "https://registry.npmjs.org/react"],
        package_sha256="9f2c1b7d4e6a8c0f3b5d7e9a1c3f5b7d9e1a3c5f7b9d1e3a5c7f9b1d3e5a7c9f",
        archive_sha256="1a3c5e7b9d1f3a5c7e9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c",
        findings=[
            PackageFinding(
                severity=s,
                code=c,
                title=t,
                detail=d,
                source="static",
                file=loc.split(":")[0],
                line=int(loc.split(":")[1]) if ":" in loc else None,
            )
            for s, c, t, loc, d in REACT_FINDINGS
        ],
        uses_eval=True,
        uses_remote_code=True,
        obfuscation_score=3,
        file_count=65,
        total_size_bytes=int(2824.9 * 1024),
        has_minified_code=True,
        manifest_version=3,
    )
    return json.dumps(pa.to_json_dict())


def generic_analysis(name: str, risk: int) -> str:
    n = len(name)
    pa = PackageAnalysis(
        permissions=["storage", "tabs"],
        host_permissions=["https://*/*"] if risk > 30 else [],
        external_domains=[f"cdn{n % 3}.example.com", "telemetry.example.net"][: 1 + risk % 2],
        package_sha256=f"{n:064x}",
        uses_eval=risk > 45,
        uses_remote_code=risk > 48,
        obfuscation_score=max(0, risk // 12),
        file_count=20 + n,
        total_size_bytes=(200 + n * 7) * 1024,
        has_minified_code=True,
        manifest_version=3,
    )
    return json.dumps(pa.to_json_dict())


PERMS = {
    "React Developer Tools": ["debugger", "storage", "scripting", "tabs"],
    "PayPal Honey: Automated Coupons & Rewards": ["storage", "tabs", "cookies", "webRequest"],
    "Session Buddy - Tab & Bookmark Manager": ["tabs", "unlimitedStorage", "storage", "alarms"],
    "Dark Reader": ["storage", "alarms", "contextMenus"],
    "LastPass: Free Password Manager": ["storage", "tabs", "cookies", "identity"],
    "Grammarly: AI Writing Assistant and Grammar Checker App": ["storage", "scripting", "contextMenus"],
    "uBlock Origin": ["storage", "webRequest", "declarativeNetRequest"],
}


DEST_LABEL = "SOC Slack #ext-alerts"
DEMO_KEYS = [(e[1], e[3]) for e in EXTS]  # (store, extension_id) pairs this script seeds
OPT_IN_ENV = "ICEBERG_EBS_SCREENSHOT_SEED"
DEMO_USER_ENV = "ICEBERG_EBS_SCREENSHOT_DEMO_USER"
DEMO_PASSWORD_ENV = "ICEBERG_EBS_SCREENSHOT_DEMO_PASSWORD"

# The demo data is owned by a dedicated account, never the real admin — see
# _ensure_demo_user for why (store IDs are not script-owned identifiers).
DEMO_USER = os.environ.get(DEMO_USER_ENV, "demo")
DEMO_PASSWORD = os.environ.get(DEMO_PASSWORD_ENV, "")


def _assert_safe_target() -> None:
    """Fail closed unless this is plainly a local development database.

    This script deletes rows, and deleting an Extension cascades into its FetchLog,
    InstallCountHistory, InstallObservation, AlertRule and AlertLog history. A README
    warning is not a control, so refuse outright rather than trusting the operator to
    have pointed ICEBERG_EBS_DATABASE_URL somewhere disposable.
    """
    if os.environ.get(OPT_IN_ENV) != "1":
        raise SystemExit(
            f"refusing to seed: set {OPT_IN_ENV}=1 to confirm this database is disposable.\n"
            "It is the same database a bare `uv run pytest` truncates — never a real one."
        )
    url = make_url(settings.database_url)
    host = (url.host or "").lower()
    if host not in {"localhost", "127.0.0.1", "::1", ""}:
        raise SystemExit(
            f"refusing to seed: database host {host!r} is not local. This script is for a local dev database only."
        )
    if not DEMO_PASSWORD:
        # No committed default: the demo account is a real admin login, so its
        # credential comes from the operator's environment, never from this file.
        raise SystemExit(
            f"refusing to seed: set {DEMO_PASSWORD_ENV} to the password for the "
            f"dedicated demo account ({DEMO_USER!r}). shoot.py signs in with the same value."
        )


async def _ensure_demo_user(s: AsyncSession) -> int:
    """Return the id of the dedicated demo account, creating it if absent.

    The demo data must be owned by an account this script owns. Scoping deletes by
    ``(store, extension_id)`` is NOT sufficient: DEMO_KEYS holds *real* store IDs
    (uBlock Origin's actual Chrome ID, `ms-python.python`, …), and this is an
    extension-tracking app — a developer's database plausibly already watches one, so
    a "scoped" delete would still destroy a legitimate Extension and cascade through
    its fetch history, inventory observations, rules and alert log (bot review, #315).

    A pre-existing account under this username that owns anything outside the demo set
    is treated as a collision and refused, rather than assumed to be ours.
    """
    existing = (await s.exec(select(User).where(User.username == DEMO_USER))).first()
    if existing is None:
        user = User(
            username=DEMO_USER,
            password_hash=await hash_password(DEMO_PASSWORD),
            is_admin=True,  # so the rail renders the Administration group
        )
        s.add(user)
        await s.commit()
        await s.refresh(user)
        return user.id

    uid = existing.id
    foreign_ext = (
        await s.exec(
            select(Extension.name)
            .where(Extension.user_id == uid)
            .where(tuple_(Extension.store, Extension.extension_id).notin_(DEMO_KEYS))
            .limit(1)
        )
    ).first()
    foreign_dest = (
        await s.exec(
            select(AlertDestination.label)
            .where(AlertDestination.user_id == uid)
            .where(AlertDestination.label != DEST_LABEL)
            .limit(1)
        )
    ).first()
    if foreign_ext or foreign_dest:
        owns = foreign_ext or foreign_dest
        raise SystemExit(
            f"refusing to seed: user {DEMO_USER!r} already exists and owns data this script "
            f"did not create (e.g. {owns!r}). It is not a screenshot demo account.\n"
            f"Set {DEMO_USER_ENV} to an unused username."
        )
    # Keep the password in step with the env so shoot.py can sign in.
    existing.password_hash = await hash_password(DEMO_PASSWORD)
    s.add(existing)
    await s.commit()
    return uid


async def main() -> None:
    _assert_safe_target()
    async with AsyncSession(engine) as s:
        uid = await _ensure_demo_user(s)

        # Safe to clear wholesale: everything this user owns was put there by a prior
        # run of this script (enforced by the collision check above).
        await s.exec(delete(Extension).where(Extension.user_id == uid))
        # Rules cascade from the destination via the schema's ondelete=CASCADE.
        await s.exec(delete(AlertDestination).where(AlertDestination.user_id == uid))
        await s.commit()

        made: list[Extension] = []
        for name, store, pub, ext_id, ver, risk, installs, footprint, days in EXTS:
            is_react = name == "React Developer Tools"
            ext = Extension(
                user_id=uid,
                store=store,
                extension_id=ext_id,
                name=name,
                publisher=pub,
                description=DESCRIPTIONS.get(name),
                version=ver,
                install_count=installs,
                last_updated=NOW - timedelta(days=days),
                permissions=json.dumps(PERMS.get(name, ["storage", "tabs"])),
                store_url=STORE_URL[store].format(id=ext_id),
                added_at=NOW - timedelta(days=days + 30),
                last_fetched_at=NOW - timedelta(minutes=7),
                watchlist=True,
                risk_score=risk,
                risk_detail=json.dumps(REACT_DETAIL if is_react else detail_for(risk)),
                package_analysis=react_analysis() if is_react else generic_analysis(name, risk),
                install_footprint=footprint,
            )
            s.add(ext)
            made.append(ext)
        await s.commit()
        for e in made:
            await s.refresh(e)

        # Real observations behind every cached footprint.
        for ext, (*_, footprint, _d) in zip(made, EXTS, strict=True):
            for i in range(footprint):
                s.add(
                    InstallObservation(
                        extension_id=ext.id,
                        asset_id=f"WS-{ext.id:02d}-{i:03d}",
                        asset_type="workstation" if i % 4 else "server",
                        department=DEPARTMENTS[i % len(DEPARTMENTS)],
                        source="soar",
                        first_seen=NOW - timedelta(days=45),
                        last_seen=NOW - timedelta(hours=3),
                    )
                )

        # Fetch history — gives the detail page its History tab and risk trend.
        for ext in made:
            base = ext.risk_score
            for k, delta in enumerate([-6, -6, -2, 0]):
                before = max(0, base + delta)
                after = max(0, base + (0 if k == 3 else delta + 2))
                s.add(
                    FetchLog(
                        extension_id=ext.id,
                        fetched_at=NOW - timedelta(days=(3 - k) * 2, minutes=7),
                        success=True,
                        risk_score_before=before,
                        risk_score_after=after,
                    )
                )

        dest = AlertDestination(
            user_id=uid,
            label=DEST_LABEL,
            kind="slack",
            # Deliberately NOT shaped like a real Slack token: the trailing segment of a
            # genuine incoming-webhook URL is 24 alphanumerics, which GitHub's push
            # protection (correctly) flags even when the value is all zeros. The hyphens
            # break that pattern, and it reads as a placeholder in the screenshot.
            target="https://hooks.slack.com/services/T00000000/B00000000/EXAMPLE-PLACEHOLDER-NOT-A-TOKEN",
            enabled=True,
        )
        s.add(dest)
        await s.commit()
        await s.refresh(dest)

        for event in ("permission_change", "publisher_change", "new_version", "risk_level_change"):
            s.add(AlertRule(user_id=uid, destination_id=dest.id, event_type=event, enabled=True))
        await s.commit()

        print(f"seeded {len(made)} extensions, {sum(e[7] for e in EXTS)} observations, 1 destination, 4 rules")


asyncio.run(main())
