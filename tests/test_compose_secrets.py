"""Compose must fail loudly on a missing secret, and must have exactly one credential source.

Both rules exist because of a real, repeatedly-hit failure. ``docker-compose.yml`` referenced
``${POSTGRES_PASSWORD}`` bare, and Compose resolves an unset variable to the empty string behind
a warning that scrolls past in ``up`` output. The stack then started "successfully" and failed
later, inside the app, as ``asyncpg.exceptions.InvalidPasswordError`` — a symptom that reads like
a code or networking bug rather than a missing variable, which is what made it cost so much time.

The second rule closes the reason it stayed hidden. ``docker-compose.dev.yml`` used to hardcode
``POSTGRES_PASSWORD: iceberg_ebs`` and a full ``ICEBERG_EBS_DATABASE_URL``, so ``make dev`` (which
layers dev over base) worked on a machine where a plain ``docker compose up`` was broken. Two
credential sources that can disagree means one of them silently papers over a misconfiguration.
Credentials belong in .env, referenced from the base file only.

The guard the base file uses is Compose's ``${VAR:?message}`` form, which aborts interpolation
with ``message``. Helm already had the equivalent (``| required`` in templates/secret.yaml).
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_BASE = _ROOT / "docker-compose.yml"
_DEV = _ROOT / "docker-compose.dev.yml"
_DEPLOY = _ROOT / "DEPLOYMENT.md"

# Variables carrying a credential: every reference in the base file must be guarded.
# An empty value for any of these is a security problem, not just a startup problem —
# note only SECRET_KEY has an app-side validator (config.py enforces >= 32 chars), so an
# empty ADMIN_PASSWORD would otherwise seed a passwordless admin account without complaint.
_MUST_BE_GUARDED = (
    "POSTGRES_PASSWORD",
    "ICEBERG_EBS_ADMIN_USERNAME",
    "ICEBERG_EBS_ADMIN_PASSWORD",
    "ICEBERG_EBS_SECRET_KEY",
)


def _strip_comments(text: str) -> str:
    """Drop whole-line YAML comments.

    Only full-line comments — a trailing ``#`` cannot be stripped safely, since these files
    carry values containing ``#``. Whole-line stripping is enough: the comments explaining the
    guards necessarily quote the unguarded form (``a bare ${POSTGRES_PASSWORD} ...``) as prose,
    and scanning that text would fail the guard test on documentation rather than on config.
    """
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _references(text: str, var: str) -> list[str]:
    """Every ``${var...}`` interpolation of ``var`` in live config, modifier suffix intact."""
    return re.findall(r"\$\{" + re.escape(var) + r"([^}]*)\}", _strip_comments(text))


def test_every_credential_reference_is_guarded() -> None:
    """A bare ``${VAR}`` for any credential fails: it degrades to "" instead of aborting."""
    text = _BASE.read_text()
    unguarded = {
        f"{var}{suffix}" for var in _MUST_BE_GUARDED for suffix in _references(text, var) if not suffix.startswith(":?")
    }
    assert not unguarded, (
        f"unguarded credential reference(s) in {_BASE.name}: {sorted(unguarded)}. "
        "Use ${VAR:?message} so an unset value aborts `up` with an actionable message; "
        "a bare ${VAR} (or a ${VAR:-default}) silently interpolates a usable-looking blank."
    )


def test_every_credential_is_actually_referenced() -> None:
    """Guard against the test above passing vacuously if a variable is renamed or dropped."""
    text = _BASE.read_text()
    missing = [var for var in _MUST_BE_GUARDED if not _references(text, var)]
    assert not missing, (
        f"{missing} no longer referenced in {_BASE.name} — if intentionally renamed, update "
        "_MUST_BE_GUARDED so the guard keeps covering it rather than silently passing."
    )


def _deploy_compose_blocks() -> list[str]:
    """The fenced code blocks in DEPLOYMENT.md that embed the Compose stack.

    The doc's stated purpose is hand-assembling a stack from the snippet, so the snapshot
    must carry the same guards as the real file — an operator copying it must not
    reintroduce the empty-string-credential trap (#273/#290). Scanning the whole doc would
    trip on prose; scope to the fenced block(s) that actually contain the credentials.
    """
    fences = re.findall(r"```[^\n]*\n(.*?)```", _DEPLOY.read_text(), re.DOTALL)
    return [block for block in fences if "POSTGRES_PASSWORD" in block]


def test_deployment_md_compose_snapshot_guards_credentials() -> None:
    """The embedded snapshot must use ${VAR:?} guards and carry no retired ./static mount (#290)."""
    blocks = _deploy_compose_blocks()
    assert blocks, "no embedded Compose snippet with credentials found in DEPLOYMENT.md"
    snippet = "\n".join(blocks)
    unguarded = {
        f"{var}{suffix}"
        for var in _MUST_BE_GUARDED
        for suffix in _references(snippet, var)
        if not suffix.startswith(":?")
    }
    assert not unguarded, (
        f"DEPLOYMENT.md Compose snapshot has unguarded credential reference(s): {sorted(unguarded)}. "
        "Re-sync it with docker-compose.yml (${VAR:?message}) so a copy-pasted stack fails loudly (#273/#290)."
    )
    assert "srv/static" not in snippet, (
        "DEPLOYMENT.md Compose snapshot still mounts ./static into Caddy — retired by #85 "
        "(the built static tree lives only in the app image; Caddy proxies /static to the app)."
    )


def test_dev_override_does_not_hardcode_credentials() -> None:
    """Dev must inherit .env via the base file, never define its own credentials.

    A literal here resurrects the split-brain that hid the original bug: `make dev` green,
    `docker compose up` broken, same machine, same .env.
    """
    offenders = [
        line.strip()
        for line in _DEV.read_text().splitlines()
        if not line.lstrip().startswith("#")
        # A credential-bearing key assigned something that isn't an interpolation.
        and re.match(
            r"\s*(POSTGRES_PASSWORD|POSTGRES_USER|POSTGRES_DB|ICEBERG_EBS_DATABASE_URL|"
            r"ICEBERG_EBS_ADMIN_PASSWORD|ICEBERG_EBS_SECRET_KEY)\s*:",
            line,
        )
    ]
    assert not offenders, (
        f"{_DEV.name} defines credentials directly: {offenders}. Remove them and let the base "
        "file supply them from .env, so dev and prod cannot disagree about the password."
    )
