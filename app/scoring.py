import re
from datetime import datetime, timezone
from typing import NamedTuple

from app.inspector import PackageAnalysis

# Permissions tiered by danger level
_CRITICAL_PERMISSIONS = {
    "<all_urls>", "debugger", "nativeMessaging", "proxy",
    "webRequest", "webRequestBlocking", "declarativeNetRequestWithHostAccess",
}
_HIGH_PERMISSIONS = {
    "cookies", "history", "tabs", "browsingData", "downloads",
    "management", "clipboardRead", "contentSettings", "pageCapture",
}
_MEDIUM_PERMISSIONS = {
    "storage", "notifications", "contextMenus", "bookmarks",
    "identity", "geolocation", "scripting",
}


class RiskDetail(NamedTuple):
    permissions: int
    popularity: int
    publisher: int
    staleness: int
    code_behaviour: int
    external_domains: int
    total: int
    risk_level: str


def score_permissions(permissions: list[str], host_permissions: list[str] | None = None) -> int:
    all_perms = set(permissions) | set(host_permissions or [])
    if all_perms & _CRITICAL_PERMISSIONS:
        base = 25
        extras = len(all_perms & _CRITICAL_PERMISSIONS) - 1
        return min(base + extras * 2, 25)
    if all_perms & _HIGH_PERMISSIONS:
        return 15
    if all_perms & _MEDIUM_PERMISSIONS:
        return 7
    return 0


def score_popularity(install_count: int | None, history: list[int]) -> int:
    if install_count is None:
        return 10

    if install_count < 100:
        base = 16
    elif install_count < 1_000:
        base = 8
    elif install_count < 10_000:
        base = 4
    else:
        base = 0

    # Sudden drop: >30% decline between the last two readings
    if len(history) >= 2 and history[-2] > 0:
        drop = (history[-2] - install_count) / history[-2]
        if drop > 0.30:
            base = min(base + 10, 20)

    return base


def score_publisher(
    publisher: str,
    publisher_changed: bool = False,
    publisher_verified: bool | None = None,
) -> int:
    score = 0
    if publisher_changed:
        score += 8
    if publisher_verified is False:
        score += 4
    if _looks_generic(publisher):
        score += 3
    return min(score, 15)


def score_staleness(last_updated: datetime | None) -> int:
    if last_updated is None:
        return 10

    now = datetime.now(timezone.utc)
    if last_updated.tzinfo is None:
        last_updated = last_updated.replace(tzinfo=timezone.utc)

    age_days = (now - last_updated).days
    if age_days > 365 * 3:
        return 15
    if age_days > 365 * 2:
        return 11
    if age_days > 365:
        return 7
    if age_days > 180:
        return 4
    return 0


def score_code_behaviour(analysis: PackageAnalysis | None) -> int:
    if analysis is None:
        return 7  # midpoint when package unavailable

    score = 0
    if analysis.uses_eval:
        score += 8
    if analysis.uses_remote_code:
        score += 5
    if analysis.obfuscation_score >= 6:
        score += 5
    elif analysis.obfuscation_score >= 3:
        score += 3
    return min(score, 15)


def score_external_domains(analysis: PackageAnalysis | None) -> int:
    if analysis is None:
        return 5  # midpoint when package unavailable

    count = len(analysis.external_domains)
    if count == 0:
        return 0
    if count <= 2:
        return 3
    if count <= 5:
        return 6
    return 10


def compute_risk_score(
    permissions: list[str],
    host_permissions: list[str],
    install_count: int | None,
    install_history: list[int],
    publisher: str,
    publisher_changed: bool,
    publisher_verified: bool | None,
    last_updated: datetime | None,
    analysis: PackageAnalysis | None,
) -> RiskDetail:
    p = score_permissions(permissions, host_permissions)
    pop = score_popularity(install_count, install_history)
    pub = score_publisher(publisher, publisher_changed, publisher_verified)
    stale = score_staleness(last_updated)
    code = score_code_behaviour(analysis)
    domains = score_external_domains(analysis)

    total = min(p + pop + pub + stale + code + domains, 100)
    return RiskDetail(
        permissions=p,
        popularity=pop,
        publisher=pub,
        staleness=stale,
        code_behaviour=code,
        external_domains=domains,
        total=total,
        risk_level=_risk_level(total),
    )


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _looks_generic(publisher: str) -> bool:
    if not publisher:
        return True
    lower = publisher.lower()
    generic_words = ["extension", "extensions", "tools", "addon", "addons", "plugin", "plugins"]
    # Check whole words (space-separated) and substrings (handles CamelCase like "ExtensionTools")
    if any(w in lower for w in generic_words):
        return True
    # All digits/punctuation
    if re.sub(r"[^a-zA-Z]", "", publisher) == "":
        return True
    return False


