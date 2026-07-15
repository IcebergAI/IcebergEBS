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
3. **Close out the changelog.** Rename the working section to the released version and
   date it, then open a fresh `[Unreleased]` above it:

   ```markdown
   ## [Unreleased]

   ## [0.1.0-beta.1] — 2026-07-14
   ```
4. **Open a PR** with the bump + lock + changelog, and merge it once CI is green.
5. **Tag the merge commit** on `main`, in the **SemVer** spelling, and push the tag:

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
   (`--prerelease` when the tag has a `-beta`/`-rc` suffix). A `workflow_dispatch` run of the
   same workflow is a **build-only dry run** — no push, sign, attest, or release.
6. **Check the release.** Confirm the workflow run is green, the GitHub Release exists, and the
   image verifies (below). Only a stable tag (no `-suffix`) also moves `:latest` / `:MAJOR.MINOR`.

## Verifying a release

Release images are the only deployable artefacts (the `build.yml` `:edge` / `:<sha>` images are
dev-only). Verify before deploying, and **deploy by immutable tag or digest — never `:latest`
or `:edge`.**

```bash
IMAGE=ghcr.io/icebergai/icebergebs

# SLSA build provenance (that this repo's CI built the image):
gh attestation verify "oci://${IMAGE}:v0.1.0-beta.1" --repo IcebergAI/IcebergEBS

# Keyless cosign signature (identity = the release workflow, issuer = GitHub Actions OIDC):
cosign verify "${IMAGE}:v0.1.0-beta.1" \
  --certificate-identity-regexp "^https://github.com/IcebergAI/IcebergEBS/\.github/workflows/release\.yml@refs/tags/v" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pin the verified **digest** (`ghcr.io/icebergai/icebergebs@sha256:…`) in whatever drives the
deploy — see [DEPLOYMENT.md](../DEPLOYMENT.md) for the Helm `--set image.tag=` / digest flow.

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

**Not yet automated:** a tag-triggered release workflow that *verifies the git tag matches
the `pyproject.toml` version* and cuts the GitHub Release automatically. That is tracked in
the Parity 2 (CI/CD & release engineering) milestone. Until it lands, steps 5 and 6 are
manual, and it is on you to check the tag matches.
