from app.threat_intel import build_threat_intel_indicators


def test_package_hash_uses_virustotal_file_report_link():
    package_hash = "a" * 64
    indicators = build_threat_intel_indicators({
        "package_sha256": package_hash,
    })

    hash_indicator = next(indicator for indicator in indicators if indicator["type"] == "sha256")
    vt_lookup = next(lookup for lookup in hash_indicator["lookups"] if lookup["label"] == "VirusTotal")

    assert hash_indicator["value"] == package_hash
    assert vt_lookup["url"] == f"https://www.virustotal.com/gui/file/{package_hash}/detection"


def test_archive_content_hash_is_returned_when_it_differs_from_package_hash():
    package_hash = "a" * 64
    archive_hash = "b" * 64
    indicators = build_threat_intel_indicators({
        "package_sha256": package_hash,
        "archive_sha256": archive_hash,
    })

    archive_indicator = next(indicator for indicator in indicators if indicator["value"] == archive_hash)
    vt_lookup = next(lookup for lookup in archive_indicator["lookups"] if lookup["label"] == "VirusTotal")

    assert archive_indicator["label"] == "Archive content hash"
    assert archive_indicator["description"] == (
        "SHA-256 of the archive payload inside the downloaded package. "
        "This can help when a lookup provider indexed the unpacked archive instead of the signed package."
    )
    assert vt_lookup["url"] == f"https://www.virustotal.com/gui/file/{archive_hash}/detection"


def test_archive_content_hash_is_hidden_when_it_matches_package_hash():
    package_hash = "a" * 64
    indicators = build_threat_intel_indicators({
        "package_sha256": package_hash,
        "archive_sha256": package_hash,
    })

    assert [indicator["label"] for indicator in indicators] == ["Package hash"]


def test_otx_url_links_preserve_scheme_separator():
    indicators = build_threat_intel_indicators({
        "network_callout_urls": ["http://www.w3.org/1998/Math/MathML"],
    })

    url_indicator = next(indicator for indicator in indicators if indicator["type"] == "url")
    vt_lookup = next(lookup for lookup in url_indicator["lookups"] if lookup["label"] == "VirusTotal")
    otx_lookup = next(lookup for lookup in url_indicator["lookups"] if lookup["label"] == "AlienVault OTX")

    assert vt_lookup["url"] == "https://www.virustotal.com/gui/url/aHR0cDovL3d3dy53My5vcmcvMTk5OC9NYXRoL01hdGhNTA/detection"
    assert otx_lookup["url"] == "https://otx.alienvault.com/indicator/url/http:%2F%2Fwww.w3.org%2F1998%2FMath%2FMathML"
    assert url_indicator["source"] == "Network call in code"
    assert url_indicator["section"] == "network"


def test_otx_url_links_escape_query_and_fragment_delimiters():
    indicators = build_threat_intel_indicators({
        "network_callout_urls": ["https://example.com/a?b=c&d=e#frag"],
    })

    url_indicator = next(indicator for indicator in indicators if indicator["type"] == "url")
    vt_lookup = next(lookup for lookup in url_indicator["lookups"] if lookup["label"] == "VirusTotal")
    otx_lookup = next(lookup for lookup in url_indicator["lookups"] if lookup["label"] == "AlienVault OTX")

    assert vt_lookup["url"] == "https://www.virustotal.com/gui/url/aHR0cHM6Ly9leGFtcGxlLmNvbS9hP2I9YyZkPWUjZnJhZw/detection"
    assert otx_lookup["url"] == "https://otx.alienvault.com/indicator/url/https:%2F%2Fexample.com%2Fa%3Fb%3Dc%26d%3De%23frag"


def test_referenced_urls_are_split_from_network_callouts():
    indicators = build_threat_intel_indicators({
        "network_callout_urls": ["https://api.example/data"],
        "external_urls": ["https://api.example/data", "https://docs.example/reference"],
    })

    callout = next(indicator for indicator in indicators if indicator["value"] == "https://api.example/data")
    referenced = next(indicator for indicator in indicators if indicator["value"] == "https://docs.example/reference")

    assert callout["label"] == "Network callout URL"
    assert callout["section"] == "network"
    assert referenced["label"] == "Referenced URL"
    assert referenced["section"] == "referenced"
    assert referenced["source"] == "Found in code"
    referenced_vt = next(lookup for lookup in referenced["lookups"] if lookup["label"] == "VirusTotal")
    assert referenced_vt["url"] == "https://www.virustotal.com/gui/url/aHR0cHM6Ly9kb2NzLmV4YW1wbGUvcmVmZXJlbmNl/detection"


def test_obvious_reference_noise_is_not_returned():
    indicators = build_threat_intel_indicators({
        "external_urls": [
            "http://www.w3.org/1998/Math/MathML",
            "https://github.com/example/project/blob/main/README.md",
            "https://reactjs.org/docs/error-decoder.html",
            "https://docs.example/reference",
        ],
    })

    values = {indicator["value"] for indicator in indicators}
    assert "https://docs.example/reference" in values
    assert "http://www.w3.org/1998/Math/MathML" not in values
    assert "https://github.com/example/project/blob/main/README.md" not in values
    assert "https://reactjs.org/docs/error-decoder.html" not in values


def test_virustotal_url_lookup_uses_url_identifier_for_postman_ioc():
    indicators = build_threat_intel_indicators({
        "external_urls": ["https://analytics.getpostman-beta.com/events"],
    })

    url_indicator = next(indicator for indicator in indicators if indicator["type"] == "url")
    vt_lookup = next(lookup for lookup in url_indicator["lookups"] if lookup["label"] == "VirusTotal")

    assert vt_lookup["url"] == "https://www.virustotal.com/gui/url/aHR0cHM6Ly9hbmFseXRpY3MuZ2V0cG9zdG1hbi1iZXRhLmNvbS9ldmVudHM/detection"
    assert "/gui/search/" not in vt_lookup["url"]


def test_total_indicators_are_capped():
    from app.threat_intel import MAX_THREAT_INTEL_INDICATORS

    # An adversarial package referencing far more callout URLs than the cap.
    many_urls = [f"https://callout-{i}.evil.example/beacon" for i in range(MAX_THREAT_INTEL_INDICATORS * 3)]
    indicators = build_threat_intel_indicators({
        "package_sha256": "a" * 64,
        "network_callout_urls": many_urls,
    })

    assert len(indicators) == MAX_THREAT_INTEL_INDICATORS
    # The primary package hash is appended first, so the cap never drops it.
    assert indicators[0]["type"] == "sha256"
