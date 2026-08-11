"""Focused regression coverage for risky extension-update evidence (#30)."""

from app.package_diff import diff_analysis


def test_diff_reports_only_added_risky_capabilities():
    old = {
        "permissions": ["storage"],
        "host_permissions": [],
        "external_domains": ["safe.example"],
        "uses_remote_code": False,
        "findings": [],
    }
    new = {
        "permissions": ["storage", "tabs"],
        "host_permissions": ["<all_urls>"],
        "external_domains": ["safe.example", "new.example"],
        "uses_remote_code": True,
        "findings": [
            {
                "code": "remote-code",
                "severity": "high",
                "title": "Remote code",
                "detail": "Loads remote script",
                "source": "script",
                "file": "main.js",
                "line": 4,
            }
        ],
    }
    assert diff_analysis(old, new) == {
        "added_permissions": ["<all_urls>", "tabs"],
        "remote_code_enabled": True,
        "added_domains": ["new.example"],
        "new_findings": new["findings"],
    }


def test_diff_ignores_removals_duplicates_and_malformed_history():
    assert diff_analysis(
        {"permissions": ["tabs"], "external_domains": ["old.example"], "findings": [{}]},
        {"permissions": ["storage", "storage", 7], "external_domains": [None], "findings": ["bad"]},
    ) == {"added_permissions": ["storage"]}
    assert diff_analysis({"uses_remote_code": True}, {"uses_remote_code": False}) is None
