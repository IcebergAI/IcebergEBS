"""Email (SMTP) sender (#37).

The one non-HTTP kind: it delivers over SMTP, so it deliberately does **not**
traverse the outbound proxy (that routes httpx egress only). The SMTP server is
deployment-level env config (``ICEBERG_EBS_SMTP_*``); the destination ``target`` is
a comma-separated recipient list, and the only per-destination config is an optional
subject prefix. Delivery uses stdlib ``smtplib`` offloaded to a worker thread (the
bcrypt/inspector pattern) so the blocking send never stalls the event loop.
"""

from __future__ import annotations

import smtplib
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Mapping

import anyio.to_thread
import httpx

from app.config import settings
from app.senders.base import AlertMessage, ConfigField, DestinationConfigError, SenderError, register_sender
from app.senders.content import detail_text


def _recipients(target: str) -> list[str]:
    return [addr for addr in (part.strip() for part in target.split(",")) if addr]


def _is_valid_address(addr: str) -> bool:
    _name, email = parseaddr(addr)
    if "@" not in email:
        return False
    _local, _, domain = email.rpartition("@")
    return bool(_local) and "." in domain


class EmailSender:
    kind: str = "email"
    label: str = "Email (SMTP)"
    target_label: str = "Recipient address(es), comma-separated"
    config_fields: tuple[ConfigField, ...] = (
        ConfigField("subject_prefix", "Subject prefix", required=False, placeholder="[IcebergEBS]"),
    )

    def availability(self) -> tuple[bool, str | None]:
        if not settings.smtp_host:
            return (False, "Email delivery is unavailable — SMTP is not configured (set ICEBERG_EBS_SMTP_HOST)")
        if not (settings.smtp_from or settings.smtp_username):
            return (False, "Email delivery is unavailable — no sender address (set ICEBERG_EBS_SMTP_FROM)")
        return (True, None)

    async def validate(self, target: str, config: Mapping[str, str]) -> None:
        available, reason = self.availability()
        if not available:
            raise DestinationConfigError(reason or "Email delivery is unavailable")
        recipients = _recipients(target)
        if not recipients:
            raise DestinationConfigError("At least one recipient email address is required")
        for addr in recipients:
            if not _is_valid_address(addr):
                raise DestinationConfigError(f"Invalid recipient email address: {addr}")

    async def send(
        self,
        client: httpx.AsyncClient,
        target: str,
        config: Mapping[str, str],
        message: AlertMessage,
    ) -> None:
        available, reason = self.availability()
        if not available:
            raise SenderError(reason or "Email delivery is unavailable")
        recipients = _recipients(target)
        prefix = (config.get("subject_prefix") or "").strip()
        subject = f"{prefix} {message.text}".strip() if prefix else message.text

        email_msg = EmailMessage()
        email_msg["From"] = settings.smtp_from or settings.smtp_username
        email_msg["To"] = ", ".join(recipients)
        email_msg["Subject"] = subject
        email_msg.set_content(detail_text(message))

        # smtplib is blocking — offload so the single-worker event loop / scheduler
        # isn't stalled for the duration of the SMTP handshake + send.
        await anyio.to_thread.run_sync(self._deliver, email_msg)

    def _deliver(self, email_msg: EmailMessage) -> None:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            smtp.send_message(email_msg)


register_sender(EmailSender())
