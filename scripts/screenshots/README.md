# Regenerating the documentation screenshots

`docs/screenshots/` is the canonical home; `website/docs/assets/` holds copies the
Zensical site references. `shoot.py` writes **both**, so they cannot drift.

These went stale once already — the shipped set showed a rail group and a page
chrome that had been gone for weeks, and nothing failed. There is no gate on them:
if you change the shell (rail, top bar, breadcrumb) or a page these cover, refresh
them in the same PR.

## The seed needs its own database

`seed_demo.py` **deletes every extension and all alert configuration** in whatever
database it is pointed at, and deleting an `Extension` cascades into its `FetchLog`,
`InstallCountHistory`, `InstallObservation`, `AlertRule` and `AlertLog`. So it refuses
to run against anything but a database whose name contains **`screenshot`**.

That requirement replaces trying to work out which rows the script "owns". Neither
obvious approach is sound: the seed uses **real** store IDs (uBlock Origin's actual
Chrome ID, `ms-python.python`, …) and this is an extension-tracking app, so matching
an ID proves nothing about who created the row; and no property of an existing account
proves the script created *it* either. In a database that exists only for screenshots,
everything is expendable by construction — so the script never creates a user, never
writes a credential, and never inspects an account to guess its provenance.

## Process

```bash
# 1. Postgres, plus a database that exists only for this.
make db
source .env
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" -i "$(docker compose ps -q postgres)" \
  createdb -U "$POSTGRES_USER" iceberg_ebs_screenshots

# 2. Point the app at it, so it runs migrations and seeds the admin account there.
POSTGRES_DB=iceberg_ebs_screenshots \
  docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate app

# 3. Seed. The opt-in is a required confirmation; the database-name check is the guard.
ICEBERG_EBS_SCREENSHOT_SEED=1 \
ICEBERG_EBS_DATABASE_URL="postgresql+asyncpg://$POSTGRES_USER:$POSTGRES_PASSWORD@localhost:5432/iceberg_ebs_screenshots" \
PYTHONPATH="$PWD" uv run python scripts/screenshots/seed_demo.py

# 4. Shoot. Playwright is deliberately NOT in uv.lock (see CLAUDE.md); install it into
#    a throwaway venv at the version ci.yml pins.
python3 -m venv /tmp/pwvenv && /tmp/pwvenv/bin/pip install 'playwright==1.61.0'
/tmp/pwvenv/bin/playwright install chromium   # skip if ~/.cache/ms-playwright has it
/tmp/pwvenv/bin/python scripts/screenshots/shoot.py

# 5. Put the app back on your normal dev database.
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate app
```

`shoot.py` exits non-zero on any console/page error, so a CSP violation or a broken
Alpine component fails the run instead of being quietly baked into a PNG.

## Notes

- **Geometry is fixed at 1440x900 @ deviceScaleFactor 2 (= 2880x1800).** Keep it, or
  the new shots won't sit consistently beside the ones you didn't retake.
- **The data is synthetic.** No store is contacted. The cached `install_footprint`
  on each extension is backed by real `InstallObservation` rows, so the dashboard's
  Top-exposure ranking (`risk × assets`) is internally consistent rather than a
  number that contradicts the detail page's org-footprint breakdown.
- **Three guards, all fail-closed:** `ICEBERG_EBS_SCREENSHOT_SEED=1` must be set, the
  database host must be local (`localhost` / `127.0.0.1` / `::1`), and the database name
  must contain `screenshot`.
- `shoot.py` signs in with `ICEBERG_EBS_ADMIN_USERNAME` / `ICEBERG_EBS_ADMIN_PASSWORD`
  — the admin the app seeds into the screenshot database on first start against it.
