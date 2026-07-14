"""Tests for the build-version resolver and its rendering in the rail."""

import subprocess
from unittest.mock import patch

import pytest

import app.version as version
from app.version import _format, _semver, get_version


@pytest.fixture(autouse=True)
def _clear_version_cache():
    """get_version() and _semver() are lru_cached — reset around every test."""
    get_version.cache_clear()
    _semver.cache_clear()
    yield
    get_version.cache_clear()
    _semver.cache_clear()


def test_semver_read_from_pyproject():
    """The release version comes from [project].version in the real pyproject.toml."""
    assert _semver() == "0.1.0b1"


def test_format_carries_semver_and_build():
    assert _format("142", "8ebe5f8") == "v0.1.0b1 · build 142 · 8ebe5f8"


def test_format_falls_back_when_semver_unavailable(monkeypatch, tmp_path):
    """A missing/unreadable pyproject.toml must degrade to the bare build identifier.

    This runs on every page render, so it must never be the reason a page 500s.
    """
    monkeypatch.setattr(version, "_PYPROJECT", tmp_path / "nonexistent.toml")
    _semver.cache_clear()
    assert _semver() is None
    assert _format("142", "8ebe5f8") == "build 142 · 8ebe5f8"


def test_semver_none_on_malformed_pyproject(monkeypatch, tmp_path):
    bad = tmp_path / "pyproject.toml"
    bad.write_text("this is not = valid toml [[[", encoding="utf-8")
    monkeypatch.setattr(version, "_PYPROJECT", bad)
    _semver.cache_clear()
    assert _semver() is None


def test_semver_none_when_version_key_missing(monkeypatch, tmp_path):
    noversion = tmp_path / "pyproject.toml"
    noversion.write_text('[project]\nname = "iceberg-ebs"\n', encoding="utf-8")
    monkeypatch.setattr(version, "_PYPROJECT", noversion)
    _semver.cache_clear()
    assert _semver() is None


def test_env_override_wins(monkeypatch):
    monkeypatch.setenv("ICEBERG_EBS_VERSION", "  build 999 · deadbee  ")
    # Even if git/file would resolve, the env var takes priority (and is trimmed).
    assert get_version() == "build 999 · deadbee"


def test_stamped_file_used_when_no_env(monkeypatch, tmp_path):
    monkeypatch.delenv("ICEBERG_EBS_VERSION", raising=False)
    stamp = tmp_path / "_version"
    stamp.write_text("build 200 · cafef00\n", encoding="utf-8")
    monkeypatch.setattr(version, "_VERSION_FILE", stamp)
    assert get_version() == "build 200 · cafef00"


def test_runtime_git_path(monkeypatch):
    monkeypatch.delenv("ICEBERG_EBS_VERSION", raising=False)
    monkeypatch.setattr(version, "_VERSION_FILE", version.Path("/nonexistent/_version"))

    def fake_run(cmd, **kwargs):
        out = "142\n" if "rev-list" in cmd else "8ebe5f8\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(version.subprocess, "run", fake_run)
    assert get_version() == "v0.1.0b1 · build 142 · 8ebe5f8"


def test_fallback_to_dev_when_git_unavailable(monkeypatch):
    monkeypatch.delenv("ICEBERG_EBS_VERSION", raising=False)
    monkeypatch.setattr(version, "_VERSION_FILE", version.Path("/nonexistent/_version"))
    monkeypatch.setattr(
        version.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("git not found")),
    )
    assert get_version() == "dev"


async def test_version_rendered_in_rail(client):
    """The resolved version appears in the rail of an authenticated page."""
    with patch("app.routes.ui.get_version", return_value="build 142 · 8ebe5f8"):
        r = await client.get("/help")
    assert r.status_code == 200
    body = r.text
    assert 'class="rail-version"' in body
    assert "build 142 · 8ebe5f8" in body


async def test_version_absent_from_login(anon_client):
    """The login page has no rail, so it must not show the build version."""
    r = await anon_client.get("/login")
    assert r.status_code == 200
    assert "rail-version" not in r.text
