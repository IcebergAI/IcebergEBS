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
- **The rules apply to administrators** (`enforce_admins: true`). There is no default
  bypass, including for the repository owner.

### Administrator enforcement was tested, not assumed

Both states were exercised against the live repository:

| `enforce_admins` | Direct push to `main` by an admin |
|---|---|
| `false` | **Succeeded** — `remote: Bypassed rule violations for refs/heads/main: Changes must be made through a pull request.` |
| `true` (current) | **Rejected** — `! [remote rejected] main -> main (protected branch hook declined)` |

With `enforce_admins: false` the protection was *advisory, not binding*: the pull-request
requirement, the required review, and the CI gates could all be walked past by the one
person holding admin. That is the state this repository is **not** in.

One asymmetry worth knowing if you ever have to reason about a partial bypass:
**force-push protection binds administrators even when `enforce_admins` is `false`** — a
force push during that test was rejected with `GH006`. A bypassable rule does not imply
every rule is bypassable; check the specific one.

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
merge path. Because `enforce_admins` is `true`, there is no standing bypass: obtaining one
means an administrator **temporarily disabling the protection rule itself**, which is a
deliberate, visible act rather than a quiet `git push`.

That is the intended design. Note that changing branch-protection settings is *not* gated
by branch protection, so the repository cannot lock itself out — but equally, an
administrator who turns enforcement off is making a decision that must be recorded.

If an emergency change must skip the normal review path, the incident or release record
must name:

- the **reason** the change could not wait for review,
- the **commit** that was pushed,
- the **maintainer** who approved it, and
- the **follow-up pull request** in which the change was reviewed after the fact.

Reconcile the change through a normal reviewed pull request as soon as the service is
stable.
