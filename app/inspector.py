import io
import json
import re
import zipfile
from dataclasses import dataclass, field


@dataclass
class PackageAnalysis:
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    external_domains: list[str] = field(default_factory=list)
    uses_eval: bool = False
    uses_remote_code: bool = False
    obfuscation_score: int = 0
    file_count: int = 0
    total_size_bytes: int = 0
    has_minified_code: bool = False
    manifest_version: int = 2
    # Fields extracted from the manifest that may fill gaps in store metadata
    version: str = ""
    author: str = ""  # present in some Chrome/Edge manifests as "author" field


class InspectorError(Exception):
    pass


# Domains that are noise — well-known CDNs/services not worth flagging
_SAFE_DOMAINS = {
    "googleapis.com", "gstatic.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "ajax.googleapis.com", "fonts.googleapis.com",
    "fonts.gstatic.com", "accounts.google.com", "chrome.google.com",
    "microsoft.com", "visualstudio.com", "vsassets.io",
}

_URL_RE = re.compile(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})')
_EVAL_RE = re.compile(r'\beval\s*\(|new\s+Function\s*\(')
_REMOTE_FETCH_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|xhr\.open)\s*\(\s*[\'"]https?://'
)
_IDENTIFIER_RE = re.compile(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b')


def inspect_package(data: bytes) -> PackageAnalysis:
    """Inspect a zip package (CRX or VSIX) and return a PackageAnalysis."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise InspectorError(f"Not a valid zip: {exc}")

    analysis = PackageAnalysis()
    analysis.file_count = len(zf.namelist())
    analysis.total_size_bytes = sum(i.file_size for i in zf.infolist())

    manifest = _load_manifest(zf)
    if manifest:
        _extract_manifest_fields(manifest, analysis)

    js_files = [n for n in zf.namelist() if n.endswith(".js")]
    for name in js_files:
        try:
            source = zf.read(name).decode("utf-8", errors="replace")
        except Exception:
            continue
        _analyse_js(source, analysis)

    analysis.external_domains = sorted(set(analysis.external_domains))
    analysis.obfuscation_score = min(analysis.obfuscation_score, 10)
    return analysis


def _load_manifest(zf: zipfile.ZipFile) -> dict | None:
    """Load manifest.json (Chrome/Edge) or extension/package.json (VS Code)."""
    candidates = ["manifest.json", "extension/package.json", "package.json"]
    for name in candidates:
        if name in zf.namelist():
            try:
                return json.loads(zf.read(name).decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, Exception):
                continue
    # Try case-insensitive search
    lower_map = {n.lower(): n for n in zf.namelist()}
    for candidate in candidates:
        if candidate in lower_map:
            try:
                return json.loads(zf.read(lower_map[candidate]).decode("utf-8", errors="replace"))
            except Exception:
                continue
    return None


def _extract_manifest_fields(manifest: dict, analysis: PackageAnalysis) -> None:
    analysis.manifest_version = manifest.get("manifest_version", 2)
    analysis.version = str(manifest.get("version", ""))
    # "author" may be a string or {"email": ..., "url": ...} dict
    raw_author = manifest.get("author", "")
    if isinstance(raw_author, dict):
        raw_author = raw_author.get("name", "")
    analysis.author = str(raw_author)

    # Chrome/Edge manifest
    permissions = manifest.get("permissions", [])
    if isinstance(permissions, list):
        analysis.permissions = [str(p) for p in permissions]

    host_permissions = manifest.get("host_permissions", [])
    if isinstance(host_permissions, list):
        analysis.host_permissions = [str(p) for p in host_permissions]
    elif isinstance(host_permissions, str):
        analysis.host_permissions = [host_permissions]

    # Merge host patterns from permissions (MV2 style)
    for p in list(analysis.permissions):
        if p.startswith("http") or p.startswith("<"):
            analysis.host_permissions.append(p)
            analysis.permissions.remove(p)

    # VS Code package.json — no traditional permissions model
    # but capture activation events as a proxy
    if "contributes" in manifest:
        analysis.permissions = []  # VS Code doesn't use Chrome-style permissions


def _analyse_js(source: str, analysis: PackageAnalysis) -> None:
    if _EVAL_RE.search(source):
        analysis.uses_eval = True

    if _REMOTE_FETCH_RE.search(source):
        analysis.uses_remote_code = True

    # Extract external domains
    for m in _URL_RE.finditer(source):
        domain = m.group(1).lower()
        # Strip www prefix for comparison
        base_domain = domain.lstrip("www.")
        if not _is_safe_domain(base_domain):
            analysis.external_domains.append(domain)

    # Minification detection
    lines = source.splitlines()
    if lines:
        long_lines = sum(1 for l in lines if len(l) > 500)
        if long_lines > 0 and len(lines) < 20:
            analysis.has_minified_code = True

    # Obfuscation heuristic
    score = _obfuscation_score(source)
    if score > analysis.obfuscation_score:
        analysis.obfuscation_score = score


def _is_safe_domain(domain: str) -> bool:
    for safe in _SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return True
    return False


def _obfuscation_score(source: str) -> int:
    score = 0
    identifiers = _IDENTIFIER_RE.findall(source)
    if not identifiers:
        return 0

    total = len(identifiers)
    short = sum(1 for i in identifiers if len(i) <= 2)
    single = sum(1 for i in identifiers if len(i) == 1)

    if total > 50:
        if short / total > 0.6:
            score += 4
        elif single / total > 0.6:
            score += 3

    # High ratio of escaped unicode or hex sequences
    unicode_esc = len(re.findall(r'\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}', source))
    if len(source) > 0 and unicode_esc / max(len(source), 1) > 0.05:
        score += 3

    return score
