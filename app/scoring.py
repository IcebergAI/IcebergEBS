import re
from datetime import datetime, timezone
from typing import NamedTuple, overload

from app.inspector import PackageAnalysis
from app.permissions import (
    BROAD_HOST_PATTERNS as _BROAD_HOST_PATTERNS,
)
from app.permissions import (
    CRITICAL_PERMISSIONS as _CRITICAL_PERMISSIONS,
)
from app.permissions import (
    HIGH_PERMISSIONS as _HIGH_PERMISSIONS,
)
from app.permissions import (
    MEDIUM_PERMISSIONS as _MEDIUM_PERMISSIONS,
)

_FINDING_WEIGHTS = {
    "critical": 6,
    "high": 4,
    "medium": 2,
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
    # Broad host patterns (*://*/*, http(s)://*/*) are functionally <all_urls>;
    # every spelling of "all sites" must score identically (#141). Checking the
    # union of both lists also covers MV2 manifests, where the pattern may still
    # sit in `permissions` rather than `host_permissions`.
    if all_perms & (_CRITICAL_PERMISSIONS | _BROAD_HOST_PATTERNS):
        # Any critical permission maxes out this category (capped at 25).
        return 25
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
    score += min(_score_code_findings(analysis), 7)
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
        risk_level=risk_level(total),
    )


@overload
def risk_level(score: int) -> str: ...
@overload
def risk_level(score: None) -> None: ...
def risk_level(score: int | None) -> str | None:
    """Map a 0–100 risk score to its severity band. Returns None for an unknown score.

    Single source of truth for the score → level thresholds, shared by the API
    serialiser and the alert change detector.
    """
    if score is None:
        return None
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


_GENERIC_WORDS = frozenset(
    {
        "extension",
        "extensions",
        "tool",
        "tools",
        "addon",
        "addons",
        "plugin",
        "plugins",
    }
)
# Corporate suffixes stripped before judging — "Acme Tools Inc" is a real company,
# not a generic name, so "inc" shouldn't keep it from being recognised as having a
# distinctive word.
_CORP_SUFFIXES = frozenset(
    {
        "inc",
        "llc",
        "ltd",
        "limited",
        "co",
        "corp",
        "corporation",
        "gmbh",
        "company",
    }
)


def _looks_generic(publisher: str) -> bool:
    """True if a publisher name carries no distinctive (non-generic) word.

    Tokenises on whole words (splitting CamelCase, so "ExtensionTools" → extension
    + tools) rather than matching substrings. Legitimate publishers that merely
    *contain* a generic word ("Microsoft Extensions", "Acme Tools Inc", "Toolsmith
    Software") are no longer false-flagged — only names whose every meaningful word
    is generic ("Extensions", "Tools", "ExtensionTools") are (#18).
    """
    if not publisher:
        return True
    # No letters at all (digits/punctuation only).
    if re.sub(r"[^a-zA-Z]", "", publisher) == "":
        return True
    # Split CamelCase/PascalCase boundaries so concatenated generic words count.
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", publisher)
    words = re.findall(r"[a-z0-9]+", spaced.lower())
    meaningful = [w for w in words if w not in _CORP_SUFFIXES]
    if not meaningful:
        return True
    return all(w in _GENERIC_WORDS for w in meaningful)


def _score_code_findings(analysis: PackageAnalysis) -> int:
    score = 0
    for finding in getattr(analysis, "findings", []):
        if not _counts_toward_code_behaviour(finding):
            continue
        score += _FINDING_WEIGHTS.get(finding.severity, 0)
    return score


def _counts_toward_code_behaviour(finding) -> bool:
    if finding.source == "javascript":
        return True
    if finding.code.startswith("csp_"):
        return True
    if finding.code == "manifest_v2":
        return True
    return False
