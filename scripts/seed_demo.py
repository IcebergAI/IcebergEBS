"""Seed a running IcebergEBS instance with demo data for screenshots.

Enrolls a set of well-known extensions (real store fetches — the instance needs
outbound network access), enables the watchlist on a few, pushes a small SOAR
inventory batch so install footprints / exposure render, and configures a webhook
destination plus alert rules.

Usage (see scripts/README.md):

    make db && make dev   # or any running instance
    ICEBERG_EBS_ADMIN_USERNAME=admin ICEBERG_EBS_ADMIN_PASSWORD=... \
        uv run python scripts/seed_demo.py [--base-url http://localhost:8000]

Idempotent: re-running skips duplicates (409s) and re-creates only missing
destinations/rules.
"""

import argparse
import os
import sys
import time

import httpx


def req(client: httpx.Client, method: str, url: str, **kwargs) -> httpx.Response:
    """client.request, waiting out the app-side API rate limiter (429 + Retry-After).

    A re-run answers mostly from the DB (fast 409s), which trips the limiter that a
    first run's slow store fetches never reach.
    """
    for _ in range(20):
        resp = client.request(method, url, **kwargs)
        if resp.status_code != 429:
            return resp
        time.sleep(float(resp.headers.get("Retry-After", 2)))
    return resp


# (store, id, watchlist) — popular, recognisable extensions across the three stores.
EXTENSIONS: list[tuple[str, str, bool]] = [
    ("chrome", "cjpalhdlnbpafiamejdnhcphjbkeiagm", True),  # uBlock Origin
    ("chrome", "eimadpbcbfnmbkopoojfekhnkhdbieeh", False),  # Dark Reader
    ("chrome", "kbfnbcaeplbcioakkpcpgfkobkghlhen", True),  # Grammarly
    ("chrome", "hdokiejnpimakedhajhdlcegeplioahd", True),  # LastPass
    ("chrome", "bmnlcjabgnpnenekpadlanbbkooimhnj", False),  # Honey
    ("chrome", "fmkadmapgofadopljbjfkapdkoienihi", False),  # React Developer Tools
    ("chrome", "nkbihfbeogaeaoehlefnkodbefgpgknn", True),  # MetaMask
    ("vscode", "ms-python.python", True),
    ("vscode", "esbenp.prettier-vscode", False),
    ("vscode", "dbaeumer.vscode-eslint", False),
    ("vscode", "eamodio.gitlens", False),
    ("vscode", "github.copilot", True),
    ("edge", "odfafepnkmbhccpbejgmiehpchacaeak", True),  # uBlock Origin
]

# SOAR-style install observations: (store, id) → list of (asset_id, asset_type, department).
INVENTORY: dict[tuple[str, str], list[tuple[str, str, str]]] = {
    ("chrome", "kbfnbcaeplbcioakkpcpgfkobkghlhen"): [
        (f"LAPTOP-{n:04d}", "laptop", dept)
        for n, dept in enumerate(["sales"] * 14 + ["marketing"] * 9 + ["finance"] * 6 + ["engineering"] * 3, start=1)
    ],
    ("chrome", "hdokiejnpimakedhajhdlcegeplioahd"): [
        (f"LAPTOP-{n:04d}", "laptop", dept)
        for n, dept in enumerate(["finance"] * 11 + ["sales"] * 7 + ["hr"] * 4, start=20)
    ],
    ("chrome", "cjpalhdlnbpafiamejdnhcphjbkeiagm"): [
        (f"LAPTOP-{n:04d}", "laptop", dept) for n, dept in enumerate(["engineering"] * 12 + ["security"] * 5, start=40)
    ],
    ("chrome", "nkbihfbeogaeaoehlefnkodbefgpgknn"): [
        ("LAPTOP-0061", "laptop", "engineering"),
        ("LAPTOP-0062", "laptop", "engineering"),
        ("LAPTOP-0063", "laptop", "finance"),
    ],
    ("vscode", "ms-python.python"): [(f"DEV-{n:03d}", "workstation", "engineering") for n in range(1, 19)],
    ("vscode", "github.copilot"): [(f"DEV-{n:03d}", "workstation", "engineering") for n in range(1, 13)],
}

DESTINATION = {
    "label": "SOC Slack #ext-alerts",
    # Deliberately NOT shaped like a real Slack token (short final segment) —
    # GitHub push protection blocks anything matching the incoming-webhook pattern.
    "target": "https://hooks.slack.com/services/T00000000/B00000000/DEMO",
    "enabled": True,
}
EVENT_TYPES = ["risk_level_change", "permission_change", "publisher_change", "new_version"]


def login(client: httpx.Client, base_url: str, username: str, password: str) -> None:
    resp = client.post("/login", data={"username": username, "password": password})
    if resp.status_code not in (302, 303) or "session" not in resp.headers.get("set-cookie", ""):
        sys.exit(f"login failed ({resp.status_code}) — check ICEBERG_EBS_ADMIN_USERNAME/PASSWORD")
    print(f"logged in as {username}")


def seed_extensions(client: httpx.Client) -> dict[tuple[str, str], int]:
    """Enroll EXTENSIONS (real store fetch + package inspection; slow). Returns (store,id)→db id."""
    ids: dict[tuple[str, str], int] = {}
    for store, ext_id, _ in EXTENSIONS:
        resp = req(client, "POST", "/api/extensions", json={"store": store, "extension_id": ext_id})
        if resp.status_code == 201:
            body = resp.json()
            ids[(store, ext_id)] = body["id"]
            print(f"  added {store}:{ext_id} — {body['name']} (risk {body['risk_score']})")
        elif resp.status_code == 409:
            print(f"  skip  {store}:{ext_id} — already tracked")
        else:
            print(f"  FAIL  {store}:{ext_id} — HTTP {resp.status_code}: {resp.text[:120]}")
    # Resolve db ids for everything (including pre-existing rows from earlier runs).
    listing = req(client, "GET", "/api/extensions", params={"limit": 200}).json()
    for item in listing["items"]:
        ids[(item["store"], item["extension_id"])] = item["id"]
    return ids


def seed_watchlist(client: httpx.Client, ids: dict[tuple[str, str], int]) -> None:
    for store, ext_id, watch in EXTENSIONS:
        db_id = ids.get((store, ext_id))
        if db_id is not None and watch:
            req(client, "PATCH", f"/api/extensions/{db_id}/watchlist", json={"watchlist": True})
    print("watchlist enabled on flagged extensions")


def seed_inventory(client: httpx.Client, ids: dict[tuple[str, str], int]) -> None:
    observations = [
        {
            "store": store,
            "extension_id": ext_id,
            "asset_id": asset_id,
            "asset_type": asset_type,
            "department": department,
        }
        for (store, ext_id), assets in INVENTORY.items()
        if (store, ext_id) in ids  # only extensions that enrolled — keeps scoring un-deferred
        for asset_id, asset_type, department in assets
    ]
    resp = req(client, "POST", "/api/inventory", json={"source": "crowdstrike", "observations": observations})
    if resp.status_code == 200:
        body = resp.json()
        print(f"inventory: {body['observations']} observations written")
    else:
        print(f"inventory FAILED — HTTP {resp.status_code}: {resp.text[:200]}")


def seed_alerts(client: httpx.Client) -> None:
    dests = req(client, "GET", "/api/alerts/destinations").json()
    dest = next((d for d in dests if d["label"] == DESTINATION["label"]), None)
    if dest is None:
        resp = req(client, "POST", "/api/alerts/destinations", json=DESTINATION)
        if resp.status_code != 201:
            print(f"destination FAILED — HTTP {resp.status_code}: {resp.text[:200]}")
            return
        dest = resp.json()
        print(f"created destination '{dest['label']}'")
    existing = {r["event_type"] for r in req(client, "GET", "/api/alerts/rules").json()}
    for event_type in EVENT_TYPES:
        if event_type not in existing:
            req(
                client,
                "POST",
                "/api/alerts/rules",
                json={"destination_id": dest["id"], "event_type": event_type},
            )
    print(f"alert rules in place for: {', '.join(EVENT_TYPES)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8000")
    args = parser.parse_args()

    username = os.environ.get("ICEBERG_EBS_ADMIN_USERNAME", "admin")
    password = os.environ.get("ICEBERG_EBS_ADMIN_PASSWORD", "admin")

    # Store fetches + package inspection make the add endpoint slow; be generous.
    # CSRFOriginMiddleware requires a same-origin Origin on every cookie-authenticated
    # state-changing request (login included), so set it client-wide.
    with httpx.Client(
        base_url=args.base_url,
        timeout=120.0,
        follow_redirects=False,
        headers={"Origin": args.base_url},
    ) as client:
        login(client, args.base_url, username, password)
        print("enrolling extensions (real store fetches — this takes a few minutes)…")
        ids = seed_extensions(client)
        seed_watchlist(client, ids)
        seed_inventory(client, ids)
        seed_alerts(client)
    print("done")


if __name__ == "__main__":
    main()
