#!/usr/bin/env python3
"""
IcebergEBS alert ingest — polls the IcebergEBS alert log and submits new entries to a
ticketing system.

Usage:
    python alert_ingest.py

Configuration (environment variables):
    ICEBERG_EBS_URL          Base URL of your IcebergEBS instance, e.g. https://icebergebs.example.com
    ICEBERG_EBS_USERNAME     IcebergEBS account username
    ICEBERG_EBS_PASSWORD     IcebergEBS account password
    POLL_INTERVAL       Seconds between polls (default: 300)
    STATE_FILE          Path to the JSON file used to track the last seen alert ID
                        (default: .iceberg_ebs_ingest_state.json)

The script persists the highest alert ID it has processed in STATE_FILE so that
restarts and network interruptions never cause duplicate tickets.
"""

import json
import logging
import os
import time
from pathlib import Path

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

ICEBERG_EBS_URL = os.environ["ICEBERG_EBS_URL"].rstrip("/")
ICEBERG_EBS_USERNAME = os.environ["ICEBERG_EBS_USERNAME"]
ICEBERG_EBS_PASSWORD = os.environ["ICEBERG_EBS_PASSWORD"]
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "300"))
STATE_FILE = Path(os.environ.get("STATE_FILE", ".iceberg_ebs_ingest_state.json"))

# How many alert log entries to fetch per poll. The API accepts up to 500.
FETCH_LIMIT = 500

# Only ingest alerts where the webhook delivery succeeded. Set to False if you
# want to create tickets for failed deliveries too (e.g. to investigate
# webhook outages).
SUCCESSFUL_ONLY = True


# ---------------------------------------------------------------------------
# Ticketing system — replace this stub with your real integration
# ---------------------------------------------------------------------------

def submit_ticket(alert: dict) -> None:
    """Create a ticket in your internal system for a single IcebergEBS alert.

    ``alert`` is a dict with these keys:
        id          int     IcebergEBS alert log ID (already deduplicated)
        sent_at     str     ISO-8601 timestamp of when the webhook fired
        event_type  str     One of: risk_level_change, publisher_change,
                            permission_change, new_version
        extension_id int    IcebergEBS's internal extension ID
        ext_name    str     Human-readable extension name
        dest_label  str     Alert destination label
        success     bool    Whether the webhook delivery succeeded
        error       str|None  Error message if delivery failed

    Example Jira integration:
        from jira import JIRA
        jira = JIRA(server="https://jira.example.com", basic_auth=("user", "token"))
        jira.create_issue(project="SEC", issuetype={"name": "Task"},
                          summary=_ticket_title(alert),
                          description=_ticket_body(alert))
    """
    # ---- replace below with your real call ----
    log.info("TICKET: [%s] %s — %s", alert["event_type"], alert["ext_name"], alert["sent_at"])


def _ticket_title(alert: dict) -> str:
    labels = {
        "risk_level_change": "Risk level changed",
        "publisher_change": "Publisher changed",
        "permission_change": "Permissions changed",
        "new_version": "New version released",
    }
    label = labels.get(alert["event_type"], alert["event_type"])
    return f"IcebergEBS: {label} — {alert['ext_name']}"


def _ticket_body(alert: dict) -> str:
    sent = alert["sent_at"]
    return (
        f"**Extension:** {alert['ext_name']} (ID {alert['extension_id']})\n"
        f"**Event:** {alert['event_type']}\n"
        f"**Destination:** {alert['dest_label']}\n"
        f"**Detected at:** {sent}\n"
    )


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
# IcebergEBS API client
# ---------------------------------------------------------------------------

class IcebergEBSClient:
    def __init__(self) -> None:
        self._session = httpx.Client()
        self._session.headers["User-Agent"] = "icebergebs-alert-ingest/1.0"
        self._authenticated = False

    def login(self) -> None:
        resp = self._session.post(
            f"{ICEBERG_EBS_URL}/login",
            data={"username": ICEBERG_EBS_USERNAME, "password": ICEBERG_EBS_PASSWORD},
            follow_redirects=False,
            timeout=15,
        )
        # A successful login redirects to /; a failed login stays on /login.
        if resp.status_code not in (302, 303) or "iceberg_ebs_session" not in self._session.cookies:
            raise RuntimeError(
                f"Login failed (status {resp.status_code}). "
                "Check ICEBERG_EBS_USERNAME and ICEBERG_EBS_PASSWORD."
            )
        self._authenticated = True
        log.info("Logged in to %s", ICEBERG_EBS_URL)

    def fetch_alerts(self, limit: int = FETCH_LIMIT) -> list[dict]:
        if not self._authenticated:
            self.login()

        resp = self._session.get(
            f"{ICEBERG_EBS_URL}/api/alerts/log",
            params={"limit": limit},
            timeout=15,
        )

        if resp.status_code == 401:
            # Session expired — re-authenticate once and retry.
            log.info("Session expired, re-authenticating")
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
# Poll loop
# ---------------------------------------------------------------------------

def poll(client: IcebergEBSClient, state: dict) -> None:
    try:
        alerts = client.fetch_alerts()
    except httpx.HTTPError as exc:
        log.warning("Failed to fetch alerts: %s", exc)
        return

    last_seen = state["last_seen_id"]

    # Alerts are returned newest-first; find entries we haven't processed yet.
    new_alerts = [a for a in alerts if a["id"] > last_seen]
    if not new_alerts:
        log.debug("No new alerts")
        return

    # Process in chronological order so tickets reflect the real sequence.
    new_alerts.sort(key=lambda a: a["id"])

    if SUCCESSFUL_ONLY:
        new_alerts = [a for a in new_alerts if a["success"]]

    for alert in new_alerts:
        try:
            submit_ticket(alert)
        except Exception as exc:
            log.error("Failed to submit ticket for alert %d: %s", alert["id"], exc)
            # Stop here so we retry from this alert on the next poll rather than
            # skipping it and leaving a gap in the ticket history.
            return

    # Advance the cursor to the highest ID we saw, whether or not we ticketed it
    # (a filtered-out failed alert should still advance the cursor).
    highest_id = max(a["id"] for a in new_alerts)
    if SUCCESSFUL_ONLY:
        all_new = [a for a in alerts if a["id"] > last_seen]
        highest_id = max(a["id"] for a in all_new) if all_new else highest_id

    state["last_seen_id"] = highest_id
    save_state(state)
    log.info("Processed %d new alert(s), cursor now at ID %d", len(new_alerts), highest_id)


def main() -> None:
    log.info("Starting IcebergEBS alert ingest (poll interval: %ds)", POLL_INTERVAL)
    client = IcebergEBSClient()
    state = load_state()
    log.info("Resuming from alert ID %d", state["last_seen_id"])

    while True:
        poll(client, state)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
