# scripts/

Maintenance utilities — not shipped, not imported by the app.

## Refreshing the README screenshots

The screenshots in `docs/screenshots/` are captured from a locally running,
demo-seeded instance. To refresh them after a UI change:

```bash
# 1. Run the app (dev stack, http://localhost:8000). Needs outbound network
#    access — the seed does real store fetches.
make dev            # or: make db + host-side uvicorn (see README Quick start)

# 2. Seed popular extensions, watchlist, inventory footprints, and alert config.
#    Credentials default to admin/admin; override with the values in your .env.
ICEBERG_EBS_ADMIN_USERNAME=admin ICEBERG_EBS_ADMIN_PASSWORD=... \
    uv run python scripts/seed_demo.py

# 3. Capture. Playwright is intentionally outside uv.lock — use a throwaway venv.
python -m venv /tmp/pw-venv && /tmp/pw-venv/bin/pip install playwright
/tmp/pw-venv/bin/playwright install chromium
ICEBERG_EBS_ADMIN_USERNAME=admin ICEBERG_EBS_ADMIN_PASSWORD=... \
    /tmp/pw-venv/bin/python scripts/capture_screenshots.py
```

Both scripts are idempotent — re-running the seed skips what already exists, and
the capture overwrites the PNGs in place. Captures are 1440×900 at 2× scale;
the dark-theme run only re-captures the dashboard (`dashboard-dark.png`).

Screenshots referenced from `README.md`: `dashboard.png`,
`extension-detail.png`, `add-extension.png`, `alerts-webhooks.png`,
`dashboard-dark.png`.
