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

# 2. Seed the demo workspace. The opt-in env var is a required confirmation that this
#    database is disposable — the script refuses to run without it, and refuses any
#    non-local database host.
ICEBERG_EBS_SCREENSHOT_SEED=1 PYTHONPATH="$PWD" uv run python scripts/screenshots/seed_demo.py

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
- **Deletion is scoped to the rows the script itself creates** — the exact
  `(store, extension_id)` pairs in `EXTS` and the single destination label. It does
  **not** clear the admin's other data, which matters because deleting an `Extension`
  cascades into its `FetchLog`, `InstallCountHistory`, `InstallObservation`,
  `AlertRule` and `AlertLog` history.
- **The target database is guarded, not merely documented.** `seed_demo.py` refuses to
  run unless `ICEBERG_EBS_SCREENSHOT_SEED=1` is set *and* the resolved database host is
  local (`localhost` / `127.0.0.1` / `::1`). Both checks fail closed.
- The demo workspace is owned by the first admin user, so the rail renders the
  Administration group; nothing else about that account is touched.
