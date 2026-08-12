"""Threat-list API acceptance tests (#31)."""

from datetime import datetime, timezone

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension
from app.routes.api import normalise_extension_id


def test_vscode_enrollment_identity_is_canonicalized():
    assert normalise_extension_id("vscode", "Publisher.Extension") == "publisher.extension"


async def test_threatlist_ingest_forces_existing_extension_critical(client, test_db, admin_user):
    async with AsyncSession(test_db) as session:
        ext = Extension(
            user_id=admin_user.id,
            store="chrome",
            extension_id="abc123",
            name="Example",
            publisher="Publisher",
            version="1.0.0",
            permissions="[]",
            store_url="https://chromewebstore.google.com/detail/abc123",
            risk_score=12,
            risk_detail='{"total": 12, "risk_level": "low"}',
            last_fetched_at=datetime.now(timezone.utc),
        )
        session.add(ext)
        await session.commit()
        await session.refresh(ext)
        ext_id = ext.id

    response = await client.post(
        "/api/threatlist",
        json={
            "source": "soc-feed",
            "entries": [{"store": "chrome", "extension_id": "abc123", "reason": "confirmed sample"}],
        },
    )
    assert response.status_code == 202, response.text
    assert response.json() == {"accepted": 1, "matched_extensions": 1, "alerts_queued": 1}

    async with AsyncSession(test_db) as session:
        stored = await session.get(Extension, ext_id)
        assert stored is not None
        assert stored.threat_match is True
        assert stored.risk_score == 100
        assert "threat_match" in (stored.package_analysis or "")
        # There is no destination/rule in this focused API test, so the
        # post-commit delivery path has nothing to record and acknowledges the
        # durable marker. AlertLog delivery is covered by the shared alert
        # integration tests with a matching rule.
        assert stored.pending_alert_events is None


async def test_threatlist_ingest_is_idempotent(client, test_db, admin_user):
    payload = {
        "source": "soc-feed",
        "entries": [{"store": "vscode", "extension_id": "publisher.extension", "reason": "bad"}],
    }
    first = await client.post("/api/threatlist", json=payload)
    second = await client.post("/api/threatlist", json=payload)
    assert first.status_code == second.status_code == 202
    assert second.json()["accepted"] == 1
    async with AsyncSession(test_db) as session:
        rows = (
            await session.exec(
                select(Extension).where(Extension.store == "vscode", Extension.extension_id == "publisher.extension")
            )
        ).all()
        assert rows == []
