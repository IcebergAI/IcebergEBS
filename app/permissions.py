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
}

MEDIUM_PERMISSIONS = {
    "storage",
    "notifications",
    "contextMenus",
    "bookmarks",
    "identity",
    "geolocation",
    "scripting",
}

# Host-permission patterns broad enough to reach across many/all sites.
BROAD_HOST_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}
