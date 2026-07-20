"""SOAR-fed inventory + exposure — POST /api/inventory (#29)."""

from unittest.mock import AsyncMock, patch

from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension, InstallObservation, User
from tests.conftest import cached_password_hash
from tests.test_api import _fake_metadata, _fake_vsix


def _mock_vscode():
    p = patch("app.fetchers.VSCodeFetcher")
    MockFetcher = p.start()
    MockFetcher.return_value.fetch = AsyncMock(return_value=(_fake_metadata(), _fake_vsix()))
    return p


async def test_inventory_autoenrolls_unknown_deferred(client, test_db):
    """Acceptance (#78): a SOAR batch with an unknown extension auto-enrolls it onto
    the watchlist with scoring DEFERRED to the scheduler — the request never touches
    the store — while the observation + footprint are recorded immediately. The
    extension stays unscored (risk/exposure None) until a scheduler run."""
    # No fetcher mock: deferral means the request must not perform a store fetch.
    r = await client.post(
        "/api/inventory",
        json={
            "source": "crowdstrike",
            "observations": [
                {
                    "store": "vscode",
                    "extension_id": "newpub.new-ext",
                    "asset_id": "LAPTOP-01",
                    "asset_type": "workstation",
                    "department": "Finance",
                }
            ],
        },
    )

    assert r.status_code == 200
    body = r.json()
    assert body["deferred"] == 1
    assert body["observations"] == 1
    assert body["duplicates"] == 0
    assert body["results"][0]["status"] == "deferred"
    ext_id = body["results"][0]["id"]

    # Enrolled onto the watchlist, footprint set, but not yet scored.
    detail = (await client.get(f"/api/extensions/{ext_id}")).json()
    assert detail["install_footprint"] == 1
    assert detail["watchlist"] is True  # scheduler will pick it up
    assert detail["risk_score"] is None  # deferred
    assert detail["exposure"] is None  # risk unknown → exposure unknown

    async with AsyncSession(test_db) as s:
        obs = (await s.exec(select(InstallObservation).where(InstallObservation.extension_id == ext_id))).all()
        assert len(obs) == 1
        assert obs[0].asset_id == "LAPTOP-01"
        assert obs[0].department == "Finance"
        assert obs[0].source == "crowdstrike"


async def test_inventory_deferred_enrollment_scored_on_refresh(client):
    """A deferred inventory enrollment is scored on the next scheduler run.
    Simulated here via the refresh path (same fetch_and_store scoring pipeline the
    scheduler uses), after which exposure = risk × footprint is derivable."""
    r = await client.post(
        "/api/inventory",
        json={"observations": [{"store": "vscode", "extension_id": "def.ext", "asset_id": "A"}]},
    )
    ext_id = r.json()["results"][0]["id"]
    assert (await client.get(f"/api/extensions/{ext_id}")).json()["risk_score"] is None

    p = _mock_vscode()
    try:
        refreshed = await client.post(f"/api/extensions/{ext_id}/refresh")
    finally:
        p.stop()

    assert refreshed.status_code == 200
    detail = refreshed.json()
    assert detail["risk_score"] is not None
    assert detail["install_footprint"] == 1
    assert detail["exposure"] == detail["risk_score"] * 1


async def test_inventory_idempotent_upsert(client, test_db):
    """Re-pushing the same (extension, asset) updates last_seen — no dup rows,
    footprint unchanged."""
    payload = {
        "observations": [{"store": "vscode", "extension_id": "idem.ext", "asset_id": "HOST-1", "department": "Eng"}]
    }
    # No fetcher mock needed — inventory defers scoring (#78).
    first = (await client.post("/api/inventory", json=payload)).json()
    second = (await client.post("/api/inventory", json=payload)).json()

    assert first["deferred"] == 1
    # Second push: extension already tracked → observed, not deferred.
    assert second["deferred"] == 0
    assert second["duplicates"] == 1
    ext_id = first["results"][0]["id"]

    async with AsyncSession(test_db) as s:
        obs = (await s.exec(select(InstallObservation).where(InstallObservation.extension_id == ext_id))).all()
        assert len(obs) == 1  # upserted, not duplicated
        ext = await s.get(Extension, ext_id)
        assert ext.install_footprint == 1
        assert obs[0].last_seen >= obs[0].first_seen


async def test_inventory_two_assets_two_departments(client, test_db):
    body = (
        await client.post(
            "/api/inventory",
            json={
                "observations": [
                    {"store": "vscode", "extension_id": "multi.ext", "asset_id": "A", "department": "Finance"},
                    {"store": "vscode", "extension_id": "multi.ext", "asset_id": "B", "department": "Eng"},
                ]
            },
        )
    ).json()

    assert body["observations"] == 2
    assert body["deferred"] == 1  # one new extension, both observations land on it
    ext_id = body["results"][0]["id"]
    async with AsyncSession(test_db) as s:
        ext = await s.get(Extension, ext_id)
        assert ext.install_footprint == 2
        depts = {
            o.department
            for o in (await s.exec(select(InstallObservation).where(InstallObservation.extension_id == ext_id))).all()
        }
        assert depts == {"Finance", "Eng"}


async def test_inventory_invalid_id_skipped(client, test_db):
    body = (
        await client.post(
            "/api/inventory",
            json={
                "observations": [
                    {"store": "vscode", "extension_id": "not a valid id", "asset_id": "X"},
                ]
            },
        )
    ).json()

    assert body["invalid"] == 1
    assert body["observations"] == 0
    assert body["results"][0]["status"] == "invalid"
    async with AsyncSession(test_db) as s:
        assert (await s.exec(select(InstallObservation))).all() == []


async def test_inventory_empty_asset_id_reported_invalid(client, test_db):
    """#154: a blank/whitespace asset_id must not become an InstallObservation that inflates
    install_footprint — it's reported invalid and not counted, without failing the whole batch."""
    p = _mock_vscode()
    try:
        body = (
            await client.post(
                "/api/inventory",
                json={
                    "observations": [
                        {"store": "vscode", "extension_id": "pub.ext", "asset_id": ""},
                        {"store": "vscode", "extension_id": "pub.ext", "asset_id": "   "},
                        {"store": "vscode", "extension_id": "pub.ext", "asset_id": "REAL-01"},
                    ]
                },
            )
        ).json()
    finally:
        p.stop()

    assert body["invalid"] == 2
    assert body["observations"] == 1  # only the real asset counted
    statuses = [r["status"] for r in body["results"]]
    assert statuses.count("invalid") == 2
    async with AsyncSession(test_db) as s:
        obs = (await s.exec(select(InstallObservation))).all()
        assert len(obs) == 1
        assert obs[0].asset_id == "REAL-01"
        ext = (await s.exec(select(Extension).where(Extension.extension_id == "pub.ext"))).first()
        assert ext.install_footprint == 1  # not inflated by the empty asset_ids


async def test_inventory_strips_asset_id(client, test_db):
    """A surrounding-whitespace asset_id is stored trimmed, so it dedupes against the same
    trimmed asset instead of counting as a second distinct one (#154)."""
    p = _mock_vscode()
    try:
        await client.post(
            "/api/inventory",
            json={
                "observations": [
                    {"store": "vscode", "extension_id": "pub.trim", "asset_id": "  HOST-9  "},
                    {"store": "vscode", "extension_id": "pub.trim", "asset_id": "HOST-9"},
                ]
            },
        )
    finally:
        p.stop()
    async with AsyncSession(test_db) as s:
        obs = (await s.exec(select(InstallObservation))).all()
        assert len(obs) == 1  # same asset after trimming
        assert obs[0].asset_id == "HOST-9"


async def test_inventory_too_many_rejected(client):
    obs = [{"store": "vscode", "extension_id": f"pub.ext{i}", "asset_id": "A"} for i in range(1001)]
    r = await client.post("/api/inventory", json={"observations": obs})
    assert r.status_code == 422


async def test_inventory_empty_rejected(client):
    assert (await client.post("/api/inventory", json={"observations": []})).status_code == 422


async def test_inventory_requires_auth(anon_client):
    r = await anon_client.post(
        "/api/inventory",
        json={"observations": [{"store": "vscode", "extension_id": "pub.ext", "asset_id": "A"}]},
    )
    assert r.status_code == 401


async def test_inventory_is_user_scoped(client, test_db, admin_user):
    """Inventory enrolls under the caller. An identically-named extension owned by
    another user keeps its own (untouched) footprint."""
    async with AsyncSession(test_db) as s:
        other = User(username="other", password_hash=cached_password_hash("x"))
        s.add(other)
        await s.commit()
        await s.refresh(other)
        other_id = other.id  # capture before commit re-expires the detached instance
        s.add(
            Extension(
                user_id=other_id,
                store="vscode",
                extension_id="shared.ext",
                name="Shared",
                publisher="p",
                version="1.0",
                store_url="https://example.com",
            )
        )
        await s.commit()

    body = (
        await client.post(
            "/api/inventory",
            json={"observations": [{"store": "vscode", "extension_id": "shared.ext", "asset_id": "A"}]},
        )
    ).json()

    assert body["deferred"] == 1  # a NEW extension owned by the caller, not the other user's
    admin_ext_id = body["results"][0]["id"]
    async with AsyncSession(test_db) as s:
        rows = (await s.exec(select(Extension).where(Extension.extension_id == "shared.ext"))).all()
        assert len(rows) == 2  # one per user
        by_user = {e.user_id: e for e in rows}
        assert by_user[admin_user.id].id == admin_ext_id
        assert by_user[admin_user.id].install_footprint == 1
        assert by_user[other_id].install_footprint is None  # untouched


async def test_exposure_sort(client, test_db):
    """sort=exposure orders by risk × footprint via build_extension_query."""
    # Inventory defers scoring (#78); push the footprints, then score via refresh
    # (the scheduler's pipeline) so exposure = risk × footprint is populated.
    inv = (
        await client.post(
            "/api/inventory",
            json={
                "observations": [
                    {"store": "vscode", "extension_id": "low.ext", "asset_id": "A"},
                    {"store": "vscode", "extension_id": "high.ext", "asset_id": "A"},
                    {"store": "vscode", "extension_id": "high.ext", "asset_id": "B"},
                    {"store": "vscode", "extension_id": "high.ext", "asset_id": "C"},
                ]
            },
        )
    ).json()

    p = _mock_vscode()
    try:
        # Same risk score for both (deterministic mock); footprints differ → exposure differs.
        for ext_id in {r["id"] for r in inv["results"]}:
            await client.post(f"/api/extensions/{ext_id}/refresh")
    finally:
        p.stop()

    body = (await client.get("/api/extensions?sort=exposure&order=desc")).json()
    ids = [(i["extension_id"], i["exposure"]) for i in body["items"]]
    # high.ext (footprint 3) ranks above low.ext (footprint 1).
    high = next(e for x, e in ids if x == "high.ext")
    low = next(e for x, e in ids if x == "low.ext")
    assert high > low
    assert [x for x, _ in ids][:2] == ["high.ext", "low.ext"]


async def test_inventory_upsert_refreshes_metadata(client, test_db):
    """Regression (#76): the ON CONFLICT upsert refreshes asset metadata and
    bumps last_seen on a re-push, without creating a second row."""
    p = _mock_vscode()
    try:
        first = (
            await client.post(
                "/api/inventory",
                json={
                    "observations": [
                        {"store": "vscode", "extension_id": "up.ext", "asset_id": "H1", "department": "Eng"}
                    ]
                },
            )
        ).json()
        # Re-push the same (extension, asset) with a different department.
        await client.post(
            "/api/inventory",
            json={
                "observations": [{"store": "vscode", "extension_id": "up.ext", "asset_id": "H1", "department": "Sales"}]
            },
        )
    finally:
        p.stop()

    ext_id = first["results"][0]["id"]
    async with AsyncSession(test_db) as s:
        obs = (await s.exec(select(InstallObservation).where(InstallObservation.extension_id == ext_id))).all()
    assert len(obs) == 1  # upserted, not duplicated
    assert obs[0].department == "Sales"  # ON CONFLICT DO UPDATE refreshed the metadata
    assert obs[0].last_seen >= obs[0].first_seen


async def test_enroll_extension_insert_race_returns_duplicate(test_db, admin_user):
    """Regression (#76): if a concurrent insert wins the (user, store, id) unique
    constraint between the dedupe SELECT and our commit, _enroll_extension returns
    a duplicate result instead of surfacing the IntegrityError as a 500."""
    from unittest.mock import MagicMock

    import app.routes.api as api

    async with AsyncSession(test_db) as session:
        # The "winner" of the race already exists in the DB.
        winner = Extension(
            user_id=admin_user.id,
            store="vscode",
            extension_id="race.ext",
            name="race.ext",
            publisher="",
            version="",
            store_url="",
        )
        session.add(winner)
        await session.commit()
        await session.refresh(winner)
        winner_id = winner.id  # capture before the conflicting commit re-expires it

        # Force the dedupe SELECT to miss on the first call (simulating the race
        # window) and hit the real lookup afterwards, so the insert conflicts.
        real_find = api._find_extension
        state = {"n": 0}

        async def flaky_find(*args, **kwargs):
            state["n"] += 1
            if state["n"] == 1:
                return None
            return await real_find(*args, **kwargs)

        with patch.object(api, "_find_extension", flaky_find):
            result = await api._enroll_extension("vscode", "race.ext", session, MagicMock(), user_id=admin_user.id)

    assert result["status"] == "duplicate"
    assert result["id"] == winner_id


async def test_inventory_recompute_ignores_stale_observations(client, test_db, monkeypatch):
    # A stale (extension, asset) pair the SOAR stopped reporting must not keep
    # inflating install_footprint when a new batch touches the extension (#287).
    from datetime import datetime, timedelta, timezone

    from sqlmodel import select
    from sqlmodel.ext.asyncio.session import AsyncSession

    from app.config import settings
    from app.models import Extension, InstallObservation

    monkeypatch.setattr(settings, "inventory_freshness_days", 30)

    r = await client.post(
        "/api/inventory",
        json={"observations": [{"store": "chrome", "extension_id": "a" * 32, "asset_id": "host-1"}]},
    )
    assert r.status_code == 200

    async with AsyncSession(test_db) as s:
        ext = (await s.exec(select(Extension).where(Extension.extension_id == "a" * 32))).one()
        # Backdate a second observation beyond the freshness window.
        s.add(
            InstallObservation(
                extension_id=ext.id,
                asset_id="host-gone",
                first_seen=datetime.now(timezone.utc) - timedelta(days=60),
                last_seen=datetime.now(timezone.utc) - timedelta(days=60),
            )
        )
        await s.commit()
        ext_id = ext.id

    # A new push touching the extension recomputes over fresh observations only.
    r = await client.post(
        "/api/inventory",
        json={"observations": [{"store": "chrome", "extension_id": "a" * 32, "asset_id": "host-1"}]},
    )
    assert r.status_code == 200
    async with AsyncSession(test_db) as s:
        ext = await s.get(Extension, ext_id)
        # Read inside the session: after it closes the instance is expired, and a
        # lazy attribute load under asyncpg raises MissingGreenlet.
        footprint = ext.install_footprint
    assert footprint == 1  # host-gone no longer counts
