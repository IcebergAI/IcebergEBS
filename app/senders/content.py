"""Shared human-readable rendering of an ``AlertMessage`` (#37).

The message kinds (Slack, Teams, ticketing, email) all present the same facts in
their own container; this is the one place those facts are derived so they can't
drift between channels.
"""

from __future__ import annotations

from app.senders.base import AlertMessage


def event_facts(message: AlertMessage) -> list[tuple[str, str]]:
    """Ordered (label, value) pairs describing the change — the body of a Slack
    field list, a Teams FactSet, or a ticket description."""
    facts = [
        ("Extension", f"{message.name} ({message.store})"),
        ("Event", message.event.replace("_", " ")),
        ("Change", f"{message.old} → {message.new}"),
    ]
    if message.risk_score is not None:
        facts.append(("Risk score", str(message.risk_score)))
    return facts


def detail_text(message: AlertMessage) -> str:
    """A plain multi-line rendering of ``event_facts`` — the ticket/email body."""
    lines = [f"{label}: {value}" for label, value in event_facts(message)]
    if message.store_url:
        lines.append(f"Store URL: {message.store_url}")
    if message.app_url:
        lines.append(f"IcebergEBS: {message.app_url}")
    return "\n".join(lines)
