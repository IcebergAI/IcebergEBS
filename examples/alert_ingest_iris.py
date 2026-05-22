#!/usr/bin/env python3
"""
Marvin → DFIR-IRIS alert ingest.

Polls the Marvin alert log and creates alerts in DFIR-IRIS for each new entry.

Usage:
    python alert_ingest_iris.py

Configuration (environment variables):
    MARVIN_URL          Base URL of your Marvin instance, e.g. https://marvin.example.com
    MARVIN_USERNAME     Marvin account username
    MARVIN_PASSWORD     Marvin account password

    IRIS_URL            Base URL of your IRIS instance, e.g. https://iris.example.com
    IRIS_API_KEY        IRIS API key (My settings → API Key in the IRIS UI)
    IRIS_CUSTOMER_ID    IRIS customer ID to assign alerts to (integer, default: 1)

    POLL_INTERVAL       Seconds between polls (default: 300)
    STATE_FILE          Path to JSON state file for deduplication
                        (default: .marvin_iris_state.json)
    MARVIN_BASE_URL     Optional public URL for deep-linking to extensions in IRIS alerts.
                        If set, alerts include a link like {MARVIN_BASE_URL}/extensions/{id}.
                        Usually the same as MARVIN_URL.

IRIS severity IDs (defaults, adjust to match your instance):
    1 = Informational
    2 = Low
    3 = Medium
    4 = High
    5 = Critical

IRIS alert status IDs (defaults, adjust to match your instance):
    1 = New
    2 = Assigned
    3 = In Progress
    4 = Pending
    5 = Closed
    6 = Merged
"""

import json
import logging
import os
import time
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

MARVIN_URL = os.environ["MARVIN_URL"].rstrip("/")
MARVIN_USERNAME = os.environ["MARVIN_USERNAME"]
MARVIN_PASSWORD = os.environ["MARVIN_PASSWORD"]

IRIS_URL = os.environ["IRIS_URL"].rstrip("/")
IRIS_API_KEY = os.environ["IRIS_API_KEY"]
IRIS_CUSTOMER_ID = int(os.environ.get("IRIS_CUSTOMER_ID", "1"))

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "300"))
STATE_FILE = Path(os.environ.get("STATE_FILE", ".marvin_iris_state.json"))
MARVIN_BASE_URL = os.environ.get("MARVIN_BASE_URL", MARVIN_URL)

FETCH_LIMIT = 500

# Map Marvin event types to IRIS severity IDs.
# publisher_change and risk_level_change are high because they indicate the
# extension may have changed hands or become more dangerous.
_SEVERITY = {
    "risk_level_change": 4,   # High
    "publisher_change":  4,   # High
    "permission_change": 3,   # Medium
    "new_version":       2,   # Low
}
_DEFAULT_SEVERITY = 3  # Medium for unknown event types

_EVENT_TITLES = {
    "risk_level_change": "Risk level changed",
    "publisher_change":  "Publisher changed",
    "permission_change": "Permissions changed",
    "new_version":       "New version released",
}

IRIS_STATUS_NEW = 1  # alert_status_id for "New"


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"last_seen_id": 0}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state))


# ---------------------------------------------------------------------------
# Marvin client
# ---------------------------------------------------------------------------

class MarvinClient:
    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "marvin-iris-ingest/1.0"
        self._authenticated = False

    def login(self) -> None:
        resp = self._session.post(
            f"{MARVIN_URL}/login",
            data={"username": MARVIN_USERNAME, "password": MARVIN_PASSWORD},
            allow_redirects=False,
            timeout=15,
        )
        if resp.status_code not in (302, 303) or "marvin_session" not in self._session.cookies:
            raise RuntimeError(
                f"Marvin login failed (status {resp.status_code}). "
                "Check MARVIN_USERNAME and MARVIN_PASSWORD."
            )
        self._authenticated = True
        log.info("Logged in to Marvin at %s", MARVIN_URL)

    def fetch_alerts(self, limit: int = FETCH_LIMIT) -> list[dict]:
        if not self._authenticated:
            self.login()
        resp = self._session.get(
            f"{MARVIN_URL}/api/alerts/log",
            params={"limit": limit},
            timeout=15,
        )
        if resp.status_code == 401:
            log.info("Marvin session expired, re-authenticating")
            self._authenticated = False
            self.login()
            resp = self._session.get(
                f"{MARVIN_URL}/api/alerts/log",
                params={"limit": limit},
                timeout=15,
            )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# IRIS client
# ---------------------------------------------------------------------------

class IrisClient:
    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {IRIS_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "marvin-iris-ingest/1.0",
        })

    def create_alert(self, payload: dict) -> dict:
        resp = self._session.post(
            f"{IRIS_URL}/api/v2/alerts/add",
            json=payload,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(f"IRIS returned non-success: {data}")
        return data["data"]


# ---------------------------------------------------------------------------
# Alert mapping
# ---------------------------------------------------------------------------

def _build_iris_payload(alert: dict) -> dict:
    event_type = alert["event_type"]
    ext_name = alert["ext_name"]
    ext_id = alert["extension_id"]

    title_label = _EVENT_TITLES.get(event_type, event_type.replace("_", " ").title())
    title = f"Marvin: {title_label} — {ext_name}"

    severity_id = _SEVERITY.get(event_type, _DEFAULT_SEVERITY)

    context: dict = {
        "marvin_alert_id": alert["id"],
        "extension_name": ext_name,
        "extension_id": ext_id,
        "event_type": event_type,
        "destination": alert["dest_label"],
        "detected_at": alert["sent_at"],
    }
    if MARVIN_BASE_URL:
        context["marvin_url"] = f"{MARVIN_BASE_URL}/extensions/{ext_id}"

    payload: dict = {
        "alert_title": title,
        "alert_source": "Marvin",
        "alert_source_ref": f"marvin-{alert['id']}",
        "alert_source_event_time": alert["sent_at"],
        "alert_customer_id": IRIS_CUSTOMER_ID,
        "alert_severity_id": severity_id,
        "alert_status_id": IRIS_STATUS_NEW,
        "alert_tags": f"marvin,{event_type}",
        "alert_context": context,
        "alert_source_content": alert,
    }

    if MARVIN_BASE_URL:
        payload["alert_source_link"] = f"{MARVIN_BASE_URL}/extensions/{ext_id}"

    return payload


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------

def poll(marvin: MarvinClient, iris: IrisClient, state: dict) -> None:
    try:
        alerts = marvin.fetch_alerts()
    except requests.RequestException as exc:
        log.warning("Failed to fetch Marvin alerts: %s", exc)
        return

    last_seen = state["last_seen_id"]
    all_new = [a for a in alerts if a["id"] > last_seen]
    if not all_new:
        log.debug("No new alerts")
        return

    # Process in chronological order.
    all_new.sort(key=lambda a: a["id"])

    # Only send successful webhook deliveries to IRIS; failed deliveries indicate
    # a Marvin-side webhook problem, not a genuine extension event.
    to_send = [a for a in all_new if a["success"]]

    for alert in to_send:
        payload = _build_iris_payload(alert)
        try:
            result = iris.create_alert(payload)
            log.info(
                "Created IRIS alert %d for Marvin alert %d (%s: %s)",
                result.get("alert_id", "?"),
                alert["id"],
                alert["event_type"],
                alert["ext_name"],
            )
        except Exception as exc:
            log.error(
                "Failed to create IRIS alert for Marvin alert %d: %s",
                alert["id"],
                exc,
            )
            # Stop here so the next poll retries from this alert rather than
            # skipping it and creating a gap.
            return

    # Advance cursor past all new alerts (including filtered-out failed ones).
    state["last_seen_id"] = max(a["id"] for a in all_new)
    save_state(state)
    log.info(
        "Processed %d alert(s) (%d sent to IRIS), cursor now at ID %d",
        len(all_new),
        len(to_send),
        state["last_seen_id"],
    )


def main() -> None:
    log.info(
        "Starting Marvin → IRIS ingest (poll interval: %ds, customer ID: %d)",
        POLL_INTERVAL,
        IRIS_CUSTOMER_ID,
    )
    marvin = MarvinClient()
    iris = IrisClient()
    state = load_state()
    log.info("Resuming from Marvin alert ID %d", state["last_seen_id"])

    while True:
        poll(marvin, iris, state)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
