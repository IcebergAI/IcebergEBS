"""Resolve the running build version, shown at the bottom of the left rail.

The version is a ``build N · sha`` string where ``N`` is the first-parent commit
count on ``main`` (i.e. +1 per merge) and ``sha`` is the short commit hash. It is
resolved once per process (cached) in this priority order:

1. ``MARVIN_VERSION`` env var — set by the Docker build / CI where ``.git`` is absent.
2. A stamped ``app/_version`` file — for deploy-time stamping (optional, git-ignored).
3. Runtime git — works automatically on the production git checkout: each ``git pull``
   of ``main`` advances the count and sha with no other action.
4. ``"dev"`` — when none of the above are available.
"""

import logging
import os
import subprocess  # nosec B404 - only used to run a fixed `git` argv below (no shell, no user input)
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_VERSION_FILE = Path(__file__).resolve().parent / "_version"


def _format(count: str, sha: str) -> str:
    """The single definition of the version string format (kept in sync with the
    GitHub Actions workflow that stamps MARVIN_VERSION for image builds)."""
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
    env = os.getenv("MARVIN_VERSION")
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
