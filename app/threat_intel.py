from base64 import urlsafe_b64encode
from urllib.parse import quote, urlparse

OTX_LABEL = "AlienVault OTX"
CODE_SOURCE_LABEL = "Found in code"
NETWORK_CALLOUT_SOURCE_LABEL = "Network call in code"
_REFERENCE_NOISE_DOMAINS = {
    "fb.me",
    "github.com",
    "reactjs.org",
    "w3.org",
}


def build_threat_intel_indicators(package_analysis: dict | None) -> list[dict]:
    if not package_analysis:
        return []

    indicators: list[dict] = []
    package_sha256 = package_analysis.get("package_sha256")
    if package_sha256:
        indicators.append(_indicator(
            kind="sha256",
            section="primary",
            label="Package hash",
            value=str(package_sha256),
            source="package",
            lookups=[
                _lookup("VirusTotal", f"https://www.virustotal.com/gui/file/{package_sha256}/detection"),
                _lookup(OTX_LABEL, _otx_indicator_url("file", str(package_sha256))),
            ],
        ))

    archive_sha256 = package_analysis.get("archive_sha256")
    if archive_sha256 and archive_sha256 != package_sha256:
        indicators.append(_indicator(
            kind="sha256",
            section="primary",
            label="Archive content hash",
            value=str(archive_sha256),
            source="package",
            description="SHA-256 of the archive payload inside the downloaded package. This can help when a lookup provider indexed the unpacked archive instead of the signed package.",
            lookups=[
                _lookup("VirusTotal", f"https://www.virustotal.com/gui/file/{archive_sha256}/detection"),
                _lookup(OTX_LABEL, _otx_indicator_url("file", str(archive_sha256))),
            ],
        ))

    network_callout_urls = _unique_strings(package_analysis.get("network_callout_urls", []))
    network_callout_url_set = set(network_callout_urls)
    network_callout_domains = sorted({
        domain
        for url in network_callout_urls
        if (domain := _domain_from_url(url))
    })

    for domain in network_callout_domains:
        indicators.append(_indicator(
            kind="domain",
            section="network",
            label="Network callout domain",
            value=domain,
            source=NETWORK_CALLOUT_SOURCE_LABEL,
            lookups=[
                _lookup("VirusTotal", f"https://www.virustotal.com/gui/domain/{quote(domain, safe='')}"),
                _lookup(OTX_LABEL, _otx_indicator_url("hostname", domain.lower())),
            ],
        ))

    for url in network_callout_urls:
        indicators.append(_indicator(
            kind="url",
            section="network",
            label="Network callout URL",
            value=url,
            source=NETWORK_CALLOUT_SOURCE_LABEL,
            lookups=[
                _lookup("VirusTotal", _virustotal_url_report_url(url)),
                _lookup(OTX_LABEL, _otx_indicator_url("url", url)),
            ],
        ))

    referenced_urls = [
        url
        for url in _unique_strings(package_analysis.get("external_urls", []))
        if url not in network_callout_url_set and not _is_reference_noise_url(url)
    ]
    for url in referenced_urls:
        indicators.append(_indicator(
            kind="url",
            section="referenced",
            label="Referenced URL",
            value=url,
            source=CODE_SOURCE_LABEL,
            lookups=[
                _lookup("VirusTotal", _virustotal_url_report_url(url)),
                _lookup(OTX_LABEL, _otx_indicator_url("url", url)),
            ],
        ))

    return indicators


def _indicator(
    *,
    kind: str,
    section: str,
    label: str,
    value: str,
    source: str,
    lookups: list[dict],
    description: str | None = None,
) -> dict:
    indicator = {
        "type": kind,
        "section": section,
        "label": label,
        "value": value,
        "source": source,
        "lookups": lookups,
    }
    if description:
        indicator["description"] = description
    return indicator


def _lookup(label: str, url: str, requires_copy: bool = False) -> dict:
    return {
        "label": label,
        "url": url,
        "requires_copy": requires_copy,
    }


def _unique_strings(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted({str(value) for value in values if value})


def _otx_indicator_url(kind: str, value: str) -> str:
    safe_path_chars = ":" if kind == "url" else ""
    return f"https://otx.alienvault.com/indicator/{kind}/{quote(value, safe=safe_path_chars)}"


def _virustotal_url_report_url(url: str) -> str:
    url_id = urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return f"https://www.virustotal.com/gui/url/{url_id}/detection"


def _domain_from_url(url: str) -> str:
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    return hostname if "." in hostname else ""


def _is_reference_noise_url(url: str) -> bool:
    domain = _domain_from_url(url).removeprefix("www.")
    return domain in _REFERENCE_NOISE_DOMAINS
