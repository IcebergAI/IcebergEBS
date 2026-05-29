from datetime import datetime, timedelta, timezone

import pytest

from app.inspector import PackageAnalysis, PackageFinding
from app.scoring import (
    compute_risk_score,
    score_code_behaviour,
    score_external_domains,
    score_permissions,
    score_popularity,
    score_publisher,
    score_staleness,
)


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------

def test_permissions_critical():
    assert score_permissions(["<all_urls>"], []) == 25


def test_permissions_multiple_critical_still_capped():
    # Any critical permission maxes the category; extra critical perms don't exceed the cap.
    s = score_permissions(["debugger", "nativeMessaging", "<all_urls>"], [])
    assert s == 25


def test_permissions_high():
    assert score_permissions(["cookies", "history"], []) == 15


def test_permissions_medium():
    assert score_permissions(["storage"], []) == 7


def test_permissions_empty():
    assert score_permissions([], []) == 0


def test_host_permissions_all_urls_critical():
    assert score_permissions([], ["<all_urls>"]) == 25


# ---------------------------------------------------------------------------
# Popularity
# ---------------------------------------------------------------------------

def test_popularity_very_low():
    assert score_popularity(10, []) == 16


def test_popularity_low():
    assert score_popularity(500, []) == 8


def test_popularity_medium():
    assert score_popularity(5000, []) == 4


def test_popularity_high():
    assert score_popularity(100000, []) == 0


def test_popularity_unknown():
    assert score_popularity(None, []) == 10


def test_popularity_sudden_drop():
    score = score_popularity(100, [1000, 700, 100])
    assert score > score_popularity(100, [])


def test_popularity_small_drop_not_flagged():
    score_drop = score_popularity(900, [1000, 900])
    score_flat = score_popularity(900, [])
    assert score_drop == score_flat  # <30% drop, not flagged


# ---------------------------------------------------------------------------
# Publisher
# ---------------------------------------------------------------------------

def test_publisher_changed():
    assert score_publisher("NewPublisher", publisher_changed=True) >= 8


def test_publisher_unverified():
    assert score_publisher("SomePublisher", publisher_verified=False) >= 4


def test_publisher_generic_name():
    assert score_publisher("ExtensionTools") >= 3


def test_publisher_clean():
    assert score_publisher("Mozilla", publisher_changed=False, publisher_verified=True) == 0


# ---------------------------------------------------------------------------
# Staleness
# ---------------------------------------------------------------------------

def test_staleness_recent():
    recent = datetime.now(timezone.utc) - timedelta(days=10)
    assert score_staleness(recent) == 0


def test_staleness_6_months():
    old = datetime.now(timezone.utc) - timedelta(days=200)
    assert score_staleness(old) == 4


def test_staleness_1_year():
    old = datetime.now(timezone.utc) - timedelta(days=400)
    assert score_staleness(old) == 7


def test_staleness_2_years():
    old = datetime.now(timezone.utc) - timedelta(days=800)
    assert score_staleness(old) == 11


def test_staleness_3_years():
    old = datetime.now(timezone.utc) - timedelta(days=1200)
    assert score_staleness(old) == 15


def test_staleness_unknown():
    assert score_staleness(None) == 10


# ---------------------------------------------------------------------------
# Code behaviour
# ---------------------------------------------------------------------------

def test_code_eval():
    a = PackageAnalysis(uses_eval=True)
    assert score_code_behaviour(a) >= 8


def test_code_remote():
    a = PackageAnalysis(uses_remote_code=True)
    assert score_code_behaviour(a) >= 5


def test_code_obfuscated_high():
    a = PackageAnalysis(obfuscation_score=7)
    assert score_code_behaviour(a) >= 5


def test_code_clean():
    a = PackageAnalysis()
    assert score_code_behaviour(a) == 0


def test_code_no_analysis():
    assert score_code_behaviour(None) == 7  # midpoint


def test_code_findings_increase_code_behaviour_score():
    a = PackageAnalysis(findings=[
        PackageFinding(
            code="dynamic_script_injection",
            severity="high",
            title="Dynamic script injection",
            detail="test",
            source="javascript",
        ),
        PackageFinding(
            code="string_timer_execution",
            severity="medium",
            title="String timer",
            detail="test",
            source="javascript",
        ),
    ])
    assert score_code_behaviour(a) == 6


def test_code_findings_respect_cap():
    a = PackageAnalysis(
        uses_eval=True,
        uses_remote_code=True,
        obfuscation_score=10,
        findings=[
            PackageFinding(
                code=f"remote_import_scripts_{i}",
                severity="critical",
                title="Remote importScripts",
                detail="test",
                source="javascript",
            )
            for i in range(5)
        ],
    )
    assert score_code_behaviour(a) == 15


def test_permission_findings_do_not_double_count_code_behaviour():
    a = PackageAnalysis(findings=[
        PackageFinding(
            code="high_risk_permission",
            severity="critical",
            title="Critical permission",
            detail="test",
            source="manifest",
        )
    ])
    assert score_code_behaviour(a) == 0


# ---------------------------------------------------------------------------
# External domains
# ---------------------------------------------------------------------------

def test_domains_none():
    a = PackageAnalysis(external_domains=[])
    assert score_external_domains(a) == 0


def test_domains_few():
    a = PackageAnalysis(external_domains=["a.com"])
    assert score_external_domains(a) == 3


def test_domains_many():
    a = PackageAnalysis(external_domains=["a.com", "b.com", "c.com", "d.com", "e.com", "f.com"])
    assert score_external_domains(a) == 10


def test_domains_no_analysis():
    assert score_external_domains(None) == 5  # midpoint


# ---------------------------------------------------------------------------
# Full compute
# ---------------------------------------------------------------------------

def test_compute_risk_score_high_risk():
    analysis = PackageAnalysis(
        permissions=["tabs"],
        host_permissions=["<all_urls>"],
        uses_eval=True,
        external_domains=["evil1.com", "evil2.com", "evil3.com"],
        obfuscation_score=8,
    )
    result = compute_risk_score(
        permissions=["tabs"],
        host_permissions=["<all_urls>"],
        install_count=50,
        install_history=[],
        publisher="ExtensionTools",
        publisher_changed=True,
        publisher_verified=False,
        last_updated=None,
        analysis=analysis,
    )
    assert result.total >= 50
    assert result.risk_level in ("high", "critical")


def test_compute_risk_score_low_risk():
    from datetime import datetime, timezone, timedelta
    recent = datetime.now(timezone.utc) - timedelta(days=30)
    analysis = PackageAnalysis(
        permissions=["storage"],
        host_permissions=[],
    )
    result = compute_risk_score(
        permissions=["storage"],
        host_permissions=[],
        install_count=1_000_000,
        install_history=[],
        publisher="Mozilla",
        publisher_changed=False,
        publisher_verified=True,
        last_updated=recent,
        analysis=analysis,
    )
    assert result.total < 25
    assert result.risk_level == "low"


def test_compute_risk_score_capped_at_100():
    analysis = PackageAnalysis(
        permissions=["tabs", "cookies", "history"],
        host_permissions=["<all_urls>"],
        uses_eval=True,
        uses_remote_code=True,
        obfuscation_score=10,
        external_domains=[f"evil{i}.com" for i in range(10)],
    )
    result = compute_risk_score(
        permissions=["tabs", "cookies", "history"],
        host_permissions=["<all_urls>"],
        install_count=5,
        install_history=[10000, 5],
        publisher="a",
        publisher_changed=True,
        publisher_verified=False,
        last_updated=None,
        analysis=analysis,
    )
    assert result.total <= 100
