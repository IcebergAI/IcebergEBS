import json
import re

from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension


async def _extension(test_db, admin_user, *, score: int = 63) -> int:
    async with AsyncSession(test_db) as session:
        extension = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="publisher.triage-test",
            name="Triage test",
            publisher="Publisher",
            version="1.0.0",
            store_url="https://marketplace.visualstudio.com/items?itemName=publisher.triage-test",
            risk_score=score,
            heuristic_risk_score=score,
            risk_detail=json.dumps({"total": score, "risk_level": "high"}),
        )
        session.add(extension)
        await session.commit()
        await session.refresh(extension)
        assert extension.id is not None
        return extension.id


async def test_allow_deny_and_restore_preserve_heuristic_score(client, test_db, admin_user):
    extension_id = await _extension(test_db, admin_user)

    allowed = await client.patch(
        f"/api/extensions/{extension_id}/triage",
        json={
            "triage_status": "accepted-risk",
            "triage_assignee": "  SOC queue  ",
            "triage_notes": "  Approved for the controlled pilot.  ",
            "risk_override": "allow",
        },
    )
    assert allowed.status_code == 200
    allowed_body = allowed.json()
    assert allowed_body["risk_score"] == 0
    assert allowed_body["heuristic_risk_score"] == 63
    assert allowed_body["risk_level"] == "suppressed"
    assert allowed_body["triage_status"] == "accepted-risk"
    assert allowed_body["triage_assignee"] == "SOC queue"
    assert allowed_body["triage_notes"] == "Approved for the controlled pilot."
    assert allowed_body["risk_override"] == "allow"
    detail_page = await client.get(f"/extensions/{extension_id}")
    assert detail_page.status_code == 200
    island_match = re.search(
        r'<script id="ext-data" type="application/json">(.*?)</script>',
        detail_page.text,
        re.DOTALL,
    )
    assert island_match is not None
    island = json.loads(island_match.group(1))
    assert island["triage_status"] == "accepted-risk"
    assert island["triage_assignee"] == "SOC queue"
    assert island["triage_notes"] == "Approved for the controlled pilot."
    assert island["risk_override"] == "allow"

    denied = await client.patch(f"/api/extensions/{extension_id}/triage", json={"risk_override": "deny"})
    assert denied.status_code == 200
    assert denied.json()["risk_score"] == 100
    assert denied.json()["risk_level"] == "critical"
    assert denied.json()["heuristic_risk_score"] == 63

    restored = await client.patch(
        f"/api/extensions/{extension_id}/triage",
        json={"risk_override": "none", "triage_assignee": "", "triage_notes": ""},
    )
    assert restored.status_code == 200
    assert restored.json()["risk_score"] == 63
    assert restored.json()["risk_level"] == "high"
    assert restored.json()["triage_assignee"] is None
    assert restored.json()["triage_notes"] is None


async def test_threat_intelligence_cannot_be_suppressed(client, test_db, admin_user):
    extension_id = await _extension(test_db, admin_user, score=12)
    ingested = await client.post(
        "/api/threatlist",
        json={
            "source": "triage-test",
            "entries": [
                {
                    "store": "vscode",
                    "extension_id": "publisher.triage-test",
                    "reason": "known bad",
                }
            ],
        },
    )
    assert ingested.status_code == 202

    response = await client.patch(f"/api/extensions/{extension_id}/triage", json={"risk_override": "allow"})
    assert response.status_code == 200
    assert response.json()["risk_override"] == "allow"
    assert response.json()["risk_score"] == 100
    assert response.json()["heuristic_risk_score"] == 12
    assert response.json()["risk_level"] == "critical"


async def test_triage_validation_filters_and_readonly_gate(client, readonly_api_key_client, test_db, admin_user):
    extension_id = await _extension(test_db, admin_user)
    assert (await client.patch(f"/api/extensions/{extension_id}/triage", json={})).status_code == 422
    assert (
        await client.patch(
            f"/api/extensions/{extension_id}/triage",
            json={"triage_status": "not-a-state"},
        )
    ).status_code == 422
    assert (
        await readonly_api_key_client.patch(
            f"/api/extensions/{extension_id}/triage",
            json={"triage_status": "triaging"},
        )
    ).status_code == 403

    updated = await client.patch(
        f"/api/extensions/{extension_id}/triage",
        json={"triage_status": "triaging", "risk_override": "allow"},
    )
    assert updated.status_code == 200
    triage_filtered = await client.get("/api/extensions?triage=triaging")
    suppressed = await client.get("/api/extensions?risk=suppressed")
    low = await client.get("/api/extensions?risk=low")
    assert triage_filtered.json()["total"] == 1
    assert suppressed.json()["total"] == 1
    assert low.json()["total"] == 0
    dashboard = await client.get("/?risk=suppressed&triage=triaging")
    assert dashboard.status_code == 200
    assert "Triage test" in dashboard.text
    assert "suppressed" in dashboard.text
    assert "triaging" in dashboard.text
