# Summary

<!-- What changed, and why. Lead with the problem this solves, not the diff. -->

Closes #

<!-- One `Closes #n` per issue — prose like "closes #1–#3" does not auto-close anything.
     Note that a bot merge registers the link but does NOT close the issue; verify after merge. -->

## Test evidence

<!-- What you ran and what it showed. "Tests pass" is not evidence; paste the result.
     If you changed behaviour, say how you exercised it end-to-end, not just that CI is green. -->

## Checklist

- [ ] The four CI gates pass locally: `uv run pytest`, `uv run ruff check app tests` +
      `ruff format --check app tests alembic`, `uv run mypy app`, `uv run bandit -c pyproject.toml -r app`
- [ ] **Tests added** for new behaviour, or a **regression test** if this fixes a bug
- [ ] [`CHANGELOG.md`](../CHANGELOG.md) updated under the unreleased section, if an operator would notice this
- [ ] [`CLAUDE.md`](../CLAUDE.md) updated, if this changes structure or architecture
- [ ] [`app/templates/help.html`](../app/templates/help.html) updated, if this changes user-facing behaviour
- [ ] `uv lock` re-run and `uv.lock` committed, if dependencies changed
- [ ] No secrets, credentials, or internal hostnames in the diff or the logs pasted above
