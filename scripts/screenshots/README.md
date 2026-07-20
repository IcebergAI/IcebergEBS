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

# 2. Seed the demo workspace (idempotent — it clears its own prior rows first).
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
- **`seed_demo.py` writes to whatever `ICEBERG_EBS_DATABASE_URL` points at**, which
  for local work is the dev database — the same one a bare `uv run pytest` truncates.
  Don't point it at anything you care about.
- The demo workspace is owned by the first admin user; the script deletes that
  user's extensions, destinations, and rules before reseeding.
