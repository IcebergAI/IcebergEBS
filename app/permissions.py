"""Single source of truth for Chromium extension permission tiers.

Both the scorer (`app/scoring.py`) and the static inspector (`app/inspector.py`)
classify permissions by danger level. They previously kept their own copies of
these sets; a permission added to one but not the other would score and flag
inconsistently with no test catching the drift (#63). Defining them once here and
importing into both keeps the risk score and the manifest findings in lock-step.
"""

# Any one of these maxes out the permissions risk category and is flagged
# critical by the inspector.
CRITICAL_PERMISSIONS = {
    "<all_urls>",
    "debugger",
    "nativeMessaging",
    "proxy",
    "webRequest",
    "webRequestBlocking",
    "declarativeNetRequestWithHostAccess",
    # Arbitrary screen capture — every window and app on the desktop, not just the
    # browser. The capability spyware screen-recorders are built on (#280).
    "desktopCapture",
}

HIGH_PERMISSIONS = {
    "cookies",
    "history",
    "tabs",
    "browsingData",
    "downloads",
    "management",
    "clipboardRead",
    "contentSettings",
    "pageCapture",
    # The capture/telemetry family (#280): live tab audio/video recording, device
    # capture, and the full browsing graph (webNavigation sees every navigation
    # event across every site — history-grade telemetry without the history API).
    "tabCapture",
    "audioCapture",
    "videoCapture",
    "webNavigation",
}

MEDIUM_PERMISSIONS = {
    "storage",
    "notifications",
    "contextMenus",
    "bookmarks",
    "identity",
    "geolocation",
    "scripting",
    # Surveillance-adjacent additions (#280): browser privacy-setting control,
    # recently-closed-tab access, most-visited sites, traffic rules without host
    # access (the WithHostAccess variant is CRITICAL above), and clipboard seeding
    # (reading is HIGH above).
    "privacy",
    "sessions",
    "topSites",
    "declarativeNetRequest",
    "clipboardWrite",
}

# Host-permission patterns broad enough to reach across many/all sites.
BROAD_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def permission_tier(name: str) -> str:
    """Classify one declared API permission into its severity tier.

    The render-side counterpart of the tier sets above (#281): the detail template
    used to hand-copy the sets into Jinja conditionals and drifted (missing
    declarativeNetRequestWithHostAccess, pageCapture, *://*/*), showing a grey
    "low" tag for a permission that maxes the score. Broad host patterns count as
    critical wherever they appear, matching score_permissions (#141).
    """
    if name in CRITICAL_PERMISSIONS or name in BROAD_HOST_PATTERNS:
        return "critical"
    if name in HIGH_PERMISSIONS:
        return "high"
    if name in MEDIUM_PERMISSIONS:
        return "medium"
    return "low"


def host_permission_tier(pattern: str) -> str:
    """Classify a host-permission pattern: broad patterns are critical, any other
    host access is high — same semantics the scorer applies."""
    return "critical" if pattern in BROAD_HOST_PATTERNS else "high"
