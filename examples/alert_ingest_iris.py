#!/usr/bin/env python3
"""
IcebergEBS → DFIR-IRIS alert ingest.

Polls the IcebergEBS alert log and creates alerts in DFIR-IRIS for each new entry.

Usage:
    python alert_ingest_iris.py

Configuration (environment variables):
    ICEBERG_EBS_URL          Base URL of your IcebergEBS instance, e.g. https://icebergebs.example.com
    ICEBERG_EBS_USERNAME     IcebergEBS account username
    ICEBERG_EBS_PASSWORD     IcebergEBS account password

    IRIS_URL            Base URL of your IRIS instance, e.g. https://iris.example.com
    IRIS_API_KEY        IRIS API key (My settings → API Key in the IRIS UI)
    IRIS_CUSTOMER_ID    IRIS customer ID to assign alerts to (integer, default: 1)

    POLL_INTERVAL       Seconds between polls (default: 300)
    STATE_FILE          Path to JSON state file for deduplication
                        (default: .iceberg_ebs_iris_state.json)
    ICEBERG_EBS_BASE_URL     Optional public URL for deep-linking to extensions in IRIS alerts.
                        If set, alerts include a link like {ICEBERG_EBS_BASE_URL}/extensions/{id}.
                        Usually the same as ICEBERG_EBS_URL.

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

ICEBERG_EBS_URL = os.environ["ICEBERG_EBS_URL"].rstrip("/")
ICEBERG_EBS_USERNAME = os.environ["ICEBERG_EBS_USERNAME"]
ICEBERG_EBS_PASSWORD = os.environ["ICEBERG_EBS_PASSWORD"]

IRIS_URL = os.environ["IRIS_URL"].rstrip("/")
IRIS_API_KEY = os.environ["IRIS_API_KEY"]
IRIS_CUSTOMER_ID = int(os.environ.get("IRIS_CUSTOMER_ID", "1"))

POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "300"))
STATE_FILE = Path(os.environ.get("STATE_FILE", ".iceberg_ebs_iris_state.json"))
ICEBERG_EBS_BASE_URL = os.environ.get("ICEBERG_EBS_BASE_URL", ICEBERG_EBS_URL)

FETCH_LIMIT = 500

# Map IcebergEBS event types to IRIS severity IDs.
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
# IcebergEBS client
# ---------------------------------------------------------------------------

class IcebergEBSClient:
    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "icebergebs-iris-ingest/1.0"
        self._authenticated = False

    def login(self) -> None:
        resp = self._session.post(
            f"{ICEBERG_EBS_URL}/login",
            data={"username": ICEBERG_EBS_USERNAME, "password": ICEBERG_EBS_PASSWORD},
            allow_redirects=False,
            timeout=15,
        )
        if resp.status_code not in (302, 303) or "iceberg_ebs_session" not in self._session.cookies:
            raise RuntimeError(
                f"IcebergEBS login failed (status {resp.status_code}). "
                "Check ICEBERG_EBS_USERNAME and ICEBERG_EBS_PASSWORD."
            )
        self._authenticated = True
        log.info("Logged in to IcebergEBS at %s", ICEBERG_EBS_URL)

    def fetch_alerts(self, limit: int = FETCH_LIMIT) -> list[dict]:
        if not self._authenticated:
            self.login()
        resp = self._session.get(
            f"{ICEBERG_EBS_URL}/api/alerts/log",
            params={"limit": limit},
            timeout=15,
        )
        if resp.status_code == 401:
            log.info("IcebergEBS session expired, re-authenticating")
            self._authenticated = False
            self.login()
            resp = self._session.get(
                f"{ICEBERG_EBS_URL}/api/alerts/log",
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
            "User-Agent": "icebergebs-iris-ingest/1.0",
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
    title = f"IcebergEBS: {title_label} — {ext_name}"

    severity_id = _SEVERITY.get(event_type, _DEFAULT_SEVERITY)

    context: dict = {
        "iceberg_ebs_alert_id": alert["id"],
        "extension_name": ext_name,
        "extension_id": ext_id,
        "event_type": event_type,
        "destination": alert["dest_label"],
        "detected_at": alert["sent_at"],
    }
    if ICEBERG_EBS_BASE_URL:
        context["iceberg_ebs_url"] = f"{ICEBERG_EBS_BASE_URL}/extensions/{ext_id}"

    payload: dict = {
        "alert_title": title,
        "alert_source": "IcebergEBS",
        "alert_source_ref": f"icebergebs-{alert['id']}",
        "alert_source_event_time": alert["sent_at"],
        "alert_customer_id": IRIS_CUSTOMER_ID,
        "alert_severity_id": severity_id,
        "alert_status_id": IRIS_STATUS_NEW,
        "alert_tags": f"icebergebs,{event_type}",
        "alert_context": context,
        "alert_source_content": alert,
    }

    if ICEBERG_EBS_BASE_URL:
        payload["alert_source_link"] = f"{ICEBERG_EBS_BASE_URL}/extensions/{ext_id}"

    return payload


# ---------------------------------------------------------------------------
# Poll loop
# ---------------------------------------------------------------------------

def poll(ebs: IcebergEBSClient, iris: IrisClient, state: dict) -> None:
    try:
        alerts = ebs.fetch_alerts()
    except requests.RequestException as exc:
        log.warning("Failed to fetch IcebergEBS alerts: %s", exc)
        return

    last_seen = state["last_seen_id"]
    all_new = [a for a in alerts if a["id"] > last_seen]
    if not all_new:
        log.debug("No new alerts")
        return

    # Process in chronological order.
    all_new.sort(key=lambda a: a["id"])

    # Only send successful webhook deliveries to IRIS; failed deliveries indicate
    # a IcebergEBS-side webhook problem, not a genuine extension event.
    to_send = [a for a in all_new if a["success"]]

    for alert in to_send:
        payload = _build_iris_payload(alert)
        try:
            result = iris.create_alert(payload)
            log.info(
                "Created IRIS alert %d for IcebergEBS alert %d (%s: %s)",
                result.get("alert_id", "?"),
                alert["id"],
                alert["event_type"],
                alert["ext_name"],
            )
        except Exception as exc:
            log.error(
                "Failed to create IRIS alert for IcebergEBS alert %d: %s",
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
        "Starting IcebergEBS → IRIS ingest (poll interval: %ds, customer ID: %d)",
        POLL_INTERVAL,
        IRIS_CUSTOMER_ID,
    )
    ebs = IcebergEBSClient()
    iris = IrisClient()
    state = load_state()
    log.info("Resuming from IcebergEBS alert ID %d", state["last_seen_id"])

    while True:
        poll(ebs, iris, state)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
