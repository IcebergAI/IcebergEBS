from datetime import datetime, timedelta, timezone

from sqlmodel.ext.asyncio.session import AsyncSession

from app.models import Extension, FetchLog


async def test_healthz(anon_client):
    r = await anon_client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_readyz_ok(anon_client):
    r = await anon_client.get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["database"] == "up"


async def _add_ext(session, admin_user, *, ext_id_str, last_fetched, watchlist=True):
    ext = Extension(
        user_id=admin_user.id, store="chrome", extension_id=ext_id_str, name="E",
        publisher="p", version="1.0", store_url="https://example.com",
        watchlist=watchlist, last_fetched_at=last_fetched, risk_score=10,
    )
    session.add(ext)
    await session.commit()
    await session.refresh(ext)
    return ext


async def test_dashboard_surfaces_failing_and_stale(client, test_db, admin_user):
    now = datetime.now(timezone.utc)
    async with AsyncSession(test_db) as s:
        # Healthy: recently fetched, latest log succeeded.
        healthy = await _add_ext(s, admin_user, ext_id_str="a" * 32, last_fetched=now)
        s.add(FetchLog(extension_id=healthy.id, success=True, fetched_at=now))
        # Failing: latest fetch attempt errored.
        failing = await _add_ext(s, admin_user, ext_id_str="b" * 32, last_fetched=now)
        s.add(FetchLog(extension_id=failing.id, success=True, fetched_at=now - timedelta(hours=1)))
        s.add(FetchLog(extension_id=failing.id, success=False, fetched_at=now, error_message="boom"))
        # Stale: no refresh in a long time.
        await _add_ext(s, admin_user, ext_id_str="c" * 32, last_fetched=now - timedelta(days=30))
        await s.commit()

    r = await client.get("/")
    assert r.status_code == 200
    html = r.text
    # Two of three extensions are unhealthy (failing + stale).
    assert "stale or failing" in html
    # Per-extension status reaches the embedded Alpine data.
    assert '"last_fetch_ok": false' in html
    assert '"last_fetch_error": "boom"' in html
    assert '"stale": true' in html


async def test_dashboard_all_healthy(client, test_db, admin_user):
    now = datetime.now(timezone.utc)
    async with AsyncSession(test_db) as s:
        ext = await _add_ext(s, admin_user, ext_id_str="d" * 32, last_fetched=now)
        s.add(FetchLog(extension_id=ext.id, success=True, fetched_at=now))
        await s.commit()

    r = await client.get("/")
    assert r.status_code == 200
    assert "all healthy" in r.text
