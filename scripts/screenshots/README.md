# Regenerating the documentation screenshots

`docs/screenshots/` is the canonical home; `website/docs/assets/` holds copies the
Zensical site references. `shoot.py` writes **both**, so they cannot drift.

These went stale once already — the shipped set showed a rail group and a page
chrome that had been gone for weeks, and nothing failed. There is no gate on them:
if you change the shell (rail, top bar, breadcrumb) or a page these cover, refresh
them in the same PR.

## Process

```bash
# 1. Dev stack (Postgres + app). The app must have run once so the admin is seeded.
make db
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d app

# 2. Seed the demo workspace. Both env vars are required — the script refuses to run
#    without the opt-in, without a demo password, or against a non-local database.
export ICEBERG_EBS_SCREENSHOT_SEED=1
export ICEBERG_EBS_SCREENSHOT_DEMO_PASSWORD='pick-anything-local'
PYTHONPATH="$PWD" uv run python scripts/screenshots/seed_demo.py

# 3. Shoot. Needs Playwright, which is deliberately NOT in uv.lock (see CLAUDE.md);
#    install it into a throwaway venv at the version ci.yml pins.
python3 -m venv /tmp/pwvenv && /tmp/pwvenv/bin/pip install 'playwright==1.61.0'
/tmp/pwvenv/bin/playwright install chromium   # skip if ~/.cache/ms-playwright has it
set -a; . ./.env; set +a
/tmp/pwvenv/bin/python scripts/screenshots/shoot.py
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
- **All demo data belongs to a dedicated account** (`demo` by default, override with
  `ICEBERG_EBS_SCREENSHOT_DEMO_USER`). It is an admin, so the rail renders the
  Administration group. Your real admin account is never read or modified.
  This ownership is the whole safety model: scoping deletes by `(store, extension_id)`
  is **not** sufficient, because the seed uses *real* store IDs (uBlock Origin's actual
  Chrome ID, `ms-python.python`, …) and this is an extension-tracking app — a developer's
  database plausibly already watches one. Deleting an `Extension` cascades into its
  `FetchLog`, `InstallCountHistory`, `InstallObservation`, `AlertRule` and `AlertLog`.
- **Collisions are refused, not assumed.** If the demo username already exists and owns
  anything outside the seed set, the script aborts and names the offending row rather
  than treating the account as its own.
- **The target database is guarded, not merely documented.** `seed_demo.py` refuses to
  run unless `ICEBERG_EBS_SCREENSHOT_SEED=1` is set, a demo password is supplied, *and*
  the resolved database host is local (`localhost` / `127.0.0.1` / `::1`). All fail closed.
- The demo password has **no committed default** — the account is a real admin login, so
  the credential comes from your environment. `shoot.py` reads the same two vars.
