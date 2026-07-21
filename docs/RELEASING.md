# Releasing IcebergEBS

IcebergEBS carries **two** version identifiers, on purpose. They answer different questions,
and conflating them is the mistake this document exists to prevent.

| | What it is | Where it comes from | Who needs it |
|---|---|---|---|
| **SemVer** — `0.1.0b1` | The **release** version. The only thing that can say "this release contains a breaking change" | `[project].version` in `pyproject.toml` | Humans, and API consumers (a SOAR integration pins this) |
| **`build N · sha`** | The **build** identifier: `N` = first-parent commit count on `main` (+1 per merge), `sha` = short commit | Runtime git, or the `ICEBERG_EBS_VERSION` env var baked into the image | Support — "exactly which build is this?" |

They are shown together in the rail footer: **`v0.1.0b1 · build 74 · 8823e7a`**.

`build N · sha` advances on every merge to `main` and is **not** a release. Only the
SemVer part appears in [CHANGELOG.md](../CHANGELOG.md).

## The two spellings of the same version

This is the trap. Python (PEP 440) and SemVer disagree on how to spell a pre-release,
so the same version has two forms and you must use the right one in the right place:

| `pyproject.toml` (PEP 440) | git tag (SemVer) |
|---|---|
| `0.1.0b1` | `v0.1.0-beta.1` |
| `0.1.0b2` | `v0.1.0-beta.2` |
| `0.1.0rc1` | `v0.1.0-rc.1` |
| `0.1.0` | `v0.1.0` |

**pyproject gets the PEP 440 form; the tag and the changelog heading get the SemVer form.**

## Cutting a release

1. **Bump the version** in `pyproject.toml` (PEP 440 form).
2. **Refresh the lockfile** — `uv lock`, and commit `uv.lock`. `uv.lock` records the
   project's *own* version, so skipping this makes CI's `uv lock --check` fail. This is
   the single most common way to break the build here.
3. **Match the chart's `appVersion`** — set `appVersion` in `helm/iceberg-ebs/Chart.yaml`
   to the same PEP 440 string. It advertises what the chart deploys, and `helm list`
   reports it as fact; `tests/test_helm_postgres.py` fails if the two drift (#276).
   (`version:` in that file is the *chart's* own version — bump it only when the chart
   templates change.)
4. **Close out the changelog.** Rename the working section to the released version and
   date it, then open a fresh `[Unreleased]` above it:

   ```markdown
   ## [Unreleased]

   ## [0.1.0-beta.1] — 2026-07-14
   ```
5. **Open a PR** with the bump + lock + chart + changelog, and merge it once CI is green.
6. **Tag the merge commit** on `main`, in the **SemVer** spelling, and push the tag:

   ```bash
   git checkout main && git pull
   git tag -a v0.1.0-beta.1 -m "v0.1.0-beta.1"
   git push origin v0.1.0-beta.1
   ```

   Pushing the tag is the whole release. [`.github/workflows/release.yml`](../.github/workflows/release.yml)
   fires on `v*` tags and does the rest automatically: it **verifies the tag matches
   `pyproject.toml`** (and fails the release if they disagree — see the normalization table
   above), builds and pushes the image to GHCR under its SemVer tag(s), emits an **SBOM** and
   **SLSA build provenance**, **attests** the provenance to the registry, **signs the image
   keylessly with cosign**, and **creates the GitHub Release** with generated notes
   (`--prerelease` when the tag carries any pre-release suffix — `-alpha`/`-beta`/`-rc`). A `workflow_dispatch` run of the
   same workflow is a **build-only dry run** — no push, sign, attest, or release.
7. **Check the release.** Confirm the workflow run is green, the GitHub Release exists, and the
   image verifies (below). Only a stable tag (no `-suffix`) also moves `:latest` / `:MAJOR.MINOR`.

## Verifying a release

Release images are the only deployable artefacts (the `build.yml` `:edge` / `:<sha>` images are
dev-only). Verify before deploying, and **deploy by immutable SemVer tag — never `:latest` or
`:edge`.** (Pinning by digest is stronger where your deployer supports it; the Helm chart renders
`repository:tag` only today, so digest support there is tracked in #88.)

**The image tag has no `v` prefix.** The git tag is `v0.1.0-beta.1`, but `docker/metadata-action`'s
`{{version}}` strips the leading `v`, so the pushed image is `…:0.1.0-beta.1` (verifying
`:v0.1.0-beta.1` fails with `MANIFEST_UNKNOWN`). The `@refs/tags/v` in the cosign identity regexp
below is correct — that matches the *git tag* ref, which keeps its `v`.

**GHCR release packages are private by default**, so both commands need a token with the
`read:packages` scope (separate from repo access — a `repo`-scoped token authenticates but is
denied the manifest pull). Add it with `gh auth refresh -h github.com -s read:packages`, then
`gh auth token | cosign login ghcr.io -u <you> --password-stdin`.

```bash
IMAGE=ghcr.io/icebergai/icebergebs

# SLSA build provenance (that this repo's CI built the image):
gh attestation verify "oci://${IMAGE}:0.1.0-beta.1" --repo IcebergAI/IcebergEBS

# Keyless cosign signature (identity = the release workflow, issuer = GitHub Actions OIDC):
cosign verify "${IMAGE}:0.1.0-beta.1" \
  --certificate-identity-regexp "^https://github.com/IcebergAI/IcebergEBS/\.github/workflows/release\.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Deploy the verified image by its immutable **SemVer tag** (`:0.1.0-beta.1` — no `v`) — see
[DEPLOYMENT.md](../DEPLOYMENT.md) for the Helm `--set image.tag=` flow. Digest pinning
(`…@sha256:…`) is stronger, but needs chart support the Helm chart does not have yet (#88).

## Checks that keep the versions honest

- `app/version.py:_format()` and the version-compute steps of both
  `.github/workflows/build.yml` and `.github/workflows/release.yml` build the same string. If
  you change one, change the others — a drift is invisible until a container deploy reports a
  different version from the bare-uvicorn droplet. All read the SemVer from `pyproject.toml`;
  none hardcode it. `release.yml` additionally **asserts the git tag matches** that SemVer
  before it builds anything.
- The bare-uvicorn deployment resolves the version from git at runtime, so a `git pull` of
  `main` is all it needs. The Docker/Helm images have no `.git`, so `build.yml` bakes
  `ICEBERG_EBS_VERSION` in at build time.
- `release.yml` refuses to publish unless the **tagged commit is an ancestor of `main`**, so a
  release can only ever come from reviewed, merged history — a `v*` tag on an unmerged branch is
  rejected before anything is built or signed.
