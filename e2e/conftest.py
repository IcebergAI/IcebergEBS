"""Fixtures for the Playwright UI smoke suite (#100).

This suite lives *outside* tests/ so it does NOT inherit tests/conftest.py's autouse
DB fixtures — it drives a fully running stack (Postgres + uvicorn behind the real
nginx + security_headers.conf) over HTTPS, not the ASGI app in-process. Point it at
that stack with BASE_URL (default https://localhost; the CI `ui` job uses a self-signed
dev cert). pytest-playwright is installed ephemerally by that job, not via uv.lock.
"""

import pytest


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    # The CI stack terminates TLS with a self-signed dev cert; trust it for the smoke.
    return {**browser_context_args, "ignore_https_errors": True}
