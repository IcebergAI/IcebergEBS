"""Regression coverage for the standalone ingestion examples (examples/).

These scripts are copy-paste integrations, not imported by the app, but their poll
loops are long-running and must survive a bad response rather than crash. In
particular (#250 review): httpx.Response.json() raises json.JSONDecodeError on a
malformed/non-JSON 2xx body, and that is NOT an httpx.HTTPError — so the poll
handler must catch it too, or a single bad response terminates the process.
"""

import importlib.util
import json
import os
from pathlib import Path

import pytest

_EXAMPLES = Path(__file__).resolve().parent.parent / "examples"

# The example modules read these at import time, so set them before loading.
_EXAMPLE_ENV = {
    "ICEBERG_EBS_URL": "https://iceberg.test",
    "ICEBERG_EBS_USERNAME": "user",
    "ICEBERG_EBS_PASSWORD": "pass",
    "IRIS_URL": "https://iris.test",
    "IRIS_API_KEY": "test-key",
}


def _load_example(name: str):
    for key, value in _EXAMPLE_ENV.items():
        os.environ.setdefault(key, value)
    spec = importlib.util.spec_from_file_location(f"_example_{name}", _EXAMPLES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _BadJSONClient:
    """Stub IcebergEBS client whose fetch_alerts fails exactly like
    httpx.Response.json() does on a non-JSON 2xx body."""

    def fetch_alerts(self, limit: int = 500):
        raise json.JSONDecodeError("Expecting value", "<html>not json</html>", 0)


def test_alert_ingest_poll_survives_non_json_response(caplog):
    mod = _load_example("alert_ingest")
    state = {"last_seen_id": 7}
    # Must not propagate: the loop logs and waits for the next poll.
    mod.poll(_BadJSONClient(), state)
    assert state["last_seen_id"] == 7  # cursor untouched


def test_iris_ingest_poll_survives_non_json_response(caplog):
    mod = _load_example("alert_ingest_iris")
    state = {"last_seen_id": 7}
    # iris.poll(ebs, iris, state); it fails at ebs.fetch_alerts() before touching iris.
    mod.poll(_BadJSONClient(), object(), state)
    assert state["last_seen_id"] == 7


@pytest.mark.parametrize("name", ["alert_ingest", "alert_ingest_iris"])
def test_example_poll_catches_json_decode_error(name):
    # Guard the exact regression: json.JSONDecodeError is not an httpx.HTTPError,
    # so the handler must name it explicitly.
    mod = _load_example(name)
    args = ({"last_seen_id": 0},) if name == "alert_ingest" else (object(), {"last_seen_id": 0})
    # No exception escapes.
    mod.poll(_BadJSONClient(), *args)
