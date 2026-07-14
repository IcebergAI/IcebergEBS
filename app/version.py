"""Resolve the running version, shown at the bottom of the left rail.

The version is a ``v{semver} · build N · sha`` string that carries both notions of
"version", because they answer different questions:

* **SemVer** (``v0.1.0b1``) is the *release* version, read from ``[project].version``
  in ``pyproject.toml``. It is what humans and API consumers pin to, and the only
  thing that can express "this release contains a breaking change". The git tag uses
  the SemVer spelling of the same value (``0.1.0b1`` here == tag ``v0.1.0-beta.1``) —
  see ``docs/RELEASING.md``.
* **build N · sha** is the *build* identifier: ``N`` is the first-parent commit count
  on ``main`` (i.e. +1 per merge) and ``sha`` is the short commit hash. It is what
  support needs to identify exactly which build someone is running.

Resolved once per process (cached) in this priority order:

1. ``ICEBERG_EBS_VERSION`` env var — set by the Docker build / CI where ``.git`` is absent.
   It carries a complete string and therefore wins wholesale.
2. A stamped ``app/_version`` file — for deploy-time stamping (optional, git-ignored).
   Also a complete string.
3. Runtime git + pyproject — works automatically on the production git checkout: each
   ``git pull`` of ``main`` advances the count and sha with no other action.
4. ``"dev"`` — when none of the above are available.
"""

import logging
import os
import subprocess  # nosec B404 - only used to run a fixed `git` argv below (no shell, no user input)
import tomllib
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VERSION_FILE = Path(__file__).resolve().parent / "_version"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"


@lru_cache(maxsize=1)
def _semver() -> str | None:
    """The release version from ``[project].version`` in pyproject.toml, or None.

    Never raises: this runs on every page render, so a missing or malformed
    pyproject.toml degrades to the bare build identifier rather than 500ing the UI.
    """
    try:
        with _PYPROJECT.open("rb") as fh:
            version = tomllib.load(fh)["project"]["version"]
    except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        logger.debug("Could not resolve SemVer from pyproject.toml: %s", exc)
        return None
    version = str(version).strip()
    return version or None


def _format(count: str, sha: str) -> str:
    """The single definition of the version string format (kept in sync with the
    'Compute version' step of the GitHub Actions workflow that stamps ICEBERG_EBS_VERSION
    for image builds — if you change this, change that)."""
    semver = _semver()
    if semver:
        return f"v{semver} · build {count} · {sha}"
    return f"build {count} · {sha}"


def _from_git() -> str | None:
    try:
        count = subprocess.run(  # nosec - fixed `git` argv, no shell, no untrusted input
            ["git", "rev-list", "--count", "--first-parent", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
        sha = subprocess.run(  # nosec - fixed `git` argv, no shell, no untrusted input
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=_REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        ).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.debug("Could not resolve version from git: %s", exc)
        return None
    if not count or not sha:
        return None
    return _format(count, sha)


@lru_cache(maxsize=1)
def get_version() -> str:
    """Return the build version string, resolved once and cached for the process."""
    env = os.getenv("ICEBERG_EBS_VERSION")
    if env and env.strip():
        return env.strip()

    try:
        if _VERSION_FILE.is_file():
            stamped = _VERSION_FILE.read_text(encoding="utf-8").strip()
            if stamped:
                return stamped
    except OSError as exc:
        logger.debug("Could not read stamped version file: %s", exc)

    return _from_git() or "dev"
