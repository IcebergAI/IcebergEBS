# Repository security controls

This document records the repository-level controls **verified on 2026-07-15** by reading
them back from the GitHub API after configuration — not by restating what was intended.
It contains **configuration state only**: never secrets, alert payloads, or vulnerability
details.

If you change a control, re-read it from the API and update this file. A security document
that describes controls the repository does not actually have is worse than no document,
because it stops anyone looking.

## Main branch

Verified from `GET /repos/IcebergAI/IcebergEBS/branches/main/protection`:

- **Required status checks:** `test`, `lint`, `types`, `security` — the four blocking CI
  jobs. Branches **must be up to date** with `main` before merging (`strict: true`).
  - `build` is deliberately **not** required: it runs only on pushes to `main`, never on
    pull requests, so requiring it would leave every PR waiting for a check that never
    reports.
  - The `lint-workflows` and CodeQL jobs from the Parity 2 milestone are to be **added to
    this required set** when they land.
- **One approving review** is required, and **stale approvals are dismissed** when new
  commits are pushed.
- **Review conversations must be resolved** before merge.
- **Force pushes and branch deletion are disabled.**

### Administrator enforcement is currently OFF — read this

`enforce_admins` is **`false`**. Administrators can therefore push directly to `main`,
bypassing the pull-request requirement. This was confirmed, not assumed: a direct push to
`main` succeeded with

```
remote: Bypassed rule violations for refs/heads/main:
remote: - Changes must be made through a pull request.
```

so for an administrator the branch protection is currently **advisory, not binding**.
(Force-push protection *does* still bind admins — the same test was rejected with `GH006`.)

It is set this way as a deliberate, temporary step: it mirrors the configuration the
automated reviewer is known to merge under, while we confirm that the reviewer's approval
satisfies the required-review rule. **The intent is to set `enforce_admins: true`** once
that is proven, so that the rule binds everyone. Until then, treat "changes go through a
pull request" as a convention you are trusted to follow, not a control that will stop you.

## Credential protection

Verified from `GET /repos/IcebergAI/IcebergEBS` (`security_and_analysis`) and
`GET /repos/IcebergAI/IcebergEBS/private-vulnerability-reporting`:

| Control | State |
|---|---|
| Secret scanning | **enabled** |
| Push protection | **enabled** |
| Dependabot alerts | **enabled** |
| Dependabot security updates | **enabled** |
| Private vulnerability reporting | **enabled** |
| Secret scanning — non-provider patterns | **disabled** |
| Secret scanning — validity checks | **disabled** |

The last two were **requested and did not take** — GitHub still reports them `disabled`,
so they are recorded here as disabled rather than claimed as on. Re-review that state if
the organization plan or GitHub's capabilities change.

Private vulnerability reporting is what makes the reporting path in
[SECURITY.md](../SECURITY.md) real: reports go to
`https://github.com/IcebergAI/IcebergEBS/security/advisories/new`, privately, instead of a
public issue. Dependency updates are configured in
[`.github/dependabot.yml`](../.github/dependabot.yml) (weekly, grouped, across the `uv`,
`github-actions`, `docker`, and `docker-compose` ecosystems).

**Never test push protection with a real credential.** Use GitHub's documented safe test
procedure. A "test" secret that is actually valid is an incident, not a test.

## Emergency path

An administrator bypass is an **exceptional production-recovery mechanism**, not a normal
merge path. Because `enforce_admins` is currently `false`, that bypass is available by
default — which makes the discipline below a matter of habit rather than enforcement.

If an emergency change must skip the normal review path, the incident or release record
must name:

- the **reason** the change could not wait for review,
- the **commit** that was pushed,
- the **maintainer** who approved it, and
- the **follow-up pull request** in which the change was reviewed after the fact.

Reconcile the change through a normal reviewed pull request as soon as the service is
stable.
