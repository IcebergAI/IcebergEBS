import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from hashlib import sha256

from app.permissions import BROAD_HOST_PATTERNS as _BROAD_HOST_PATTERNS
from app.permissions import CRITICAL_PERMISSIONS as _CRITICAL_PERMISSIONS
from app.permissions import HIGH_PERMISSIONS as _HIGH_PERMISSIONS
from app.utils import domain_from_url as _domain_from_url


@dataclass
class PackageFinding:
    code: str
    severity: str
    title: str
    detail: str
    source: str
    file: str | None = None
    line: int | None = None


@dataclass
class PackageAnalysis:
    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    external_domains: list[str] = field(default_factory=list)
    external_urls: list[str] = field(default_factory=list)
    network_callout_urls: list[str] = field(default_factory=list)
    package_sha256: str = ""
    archive_sha256: str = ""
    findings: list[PackageFinding] = field(default_factory=list)
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
    # Running set of finding identity tuples for O(1) dedupe in _add_finding.
    # Internal bookkeeping only — not serialized (services.py picks named fields)
    # and excluded from equality/repr so it doesn't affect comparisons or tests.
    _finding_keys: set = field(default_factory=set, compare=False, repr=False)


class InspectorError(Exception):
    pass


_MAX_FILE_COUNT = 500
_MAX_JS_BYTES = 5 * 1024 * 1024  # 5 MB per JS file
_MAX_TOTAL_BYTES = 50 * 1024 * 1024  # 50 MB total declared uncompressed
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_FINDINGS = 200
_MAX_EXTERNAL_DOMAINS = 500
_MAX_EXTERNAL_URLS = 500
_MAX_NETWORK_CALLOUT_URLS = 500
_ZIP_MAGIC = b"PK\x03\x04"


# Domains that are noise — well-known CDNs/services not worth flagging
_SAFE_DOMAINS = {
    "googleapis.com",
    "gstatic.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "accounts.google.com",
    "chrome.google.com",
    "microsoft.com",
    "visualstudio.com",
    "vsassets.io",
}

_URL_LITERAL_TAIL = r'[^\s\'"`<>{}\\]+'
_URL_RE = re.compile(r"https?://" + _URL_LITERAL_TAIL)
_EVAL_RE = re.compile(r"\beval\s*\(|new\s+Function\s*\(")
_REMOTE_FETCH_RE = re.compile(r'(?:fetch|XMLHttpRequest|xhr\.open)\s*\(\s*[\'"]https?://')
_IDENTIFIER_RE = re.compile(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b")

_EVAL_CALL_RE = re.compile(r"\beval\s*\(")
_NEW_FUNCTION_RE = re.compile(r"\bnew\s+Function\s*\(")
_STRING_TIMER_RE = re.compile(r'\bset(?:Timeout|Interval)\s*\(\s*[\'"`]')
_DYNAMIC_SCRIPT_RE = re.compile(r'\bcreateElement\s*\(\s*[\'"`]script[\'"`]\s*\)')
_REMOTE_SCRIPT_SRC_RE = re.compile(r'\.src\s*=\s*[\'"`]https?://')
_IMPORT_SCRIPTS_REMOTE_RE = re.compile(r'\bimportScripts\s*\(\s*[\'"`]https?://')
_FETCH_REMOTE_RE = re.compile(r'\bfetch\s*\(\s*[\'"`]https?://')
_XHR_REMOTE_RE = re.compile(
    r'\bnew\s+XMLHttpRequest\b|\.open\s*\(\s*[\'"`](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\'"`]\s*,\s*[\'"`]https?://',
    re.IGNORECASE,
)
_WEBSOCKET_REMOTE_RE = re.compile(r'\bnew\s+WebSocket\s*\(\s*[\'"`]wss?://', re.IGNORECASE)
_EVENTSOURCE_REMOTE_RE = re.compile(r'\bnew\s+EventSource\s*\(\s*[\'"`]https?://', re.IGNORECASE)
_SENDBEACON_REMOTE_RE = re.compile(r'\bnavigator\.sendBeacon\s*\(\s*[\'"`]https?://', re.IGNORECASE)
_NETWORK_CALLOUT_URL_PATTERNS = (
    re.compile(r'\bfetch\s*\(\s*[\'"`]((?:https?)://' + _URL_LITERAL_TAIL + r")", re.IGNORECASE),
    re.compile(r'\bimportScripts\s*\(\s*[\'"`]((?:https?)://' + _URL_LITERAL_TAIL + r")", re.IGNORECASE),
    re.compile(r'\bnew\s+WebSocket\s*\(\s*[\'"`]((?:wss?)://' + _URL_LITERAL_TAIL + r")", re.IGNORECASE),
    re.compile(r'\bnew\s+EventSource\s*\(\s*[\'"`]((?:https?)://' + _URL_LITERAL_TAIL + r")", re.IGNORECASE),
    re.compile(r'\bnavigator\.sendBeacon\s*\(\s*[\'"`]((?:https?)://' + _URL_LITERAL_TAIL + r")", re.IGNORECASE),
    re.compile(
        r'\.open\s*\(\s*[\'"`](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\'"`]\s*,\s*[\'"`]((?:https?)://'
        + _URL_LITERAL_TAIL
        + r")",
        re.IGNORECASE,
    ),
    re.compile(r'\.src\s*=\s*[\'"`]((?:https?)://' + _URL_LITERAL_TAIL + r")", re.IGNORECASE),
)


def inspect_package(data: bytes) -> PackageAnalysis:
    """Inspect a zip package (CRX or VSIX) and return a PackageAnalysis."""
    try:
        zip_payload = _zip_payload(data)
        zf = zipfile.ZipFile(io.BytesIO(zip_payload))
    except zipfile.BadZipFile as exc:
        raise InspectorError(f"Not a valid zip or CRX: {exc}") from exc

    infolist = zf.infolist()
    if len(infolist) > _MAX_FILE_COUNT:
        raise InspectorError(f"Package contains too many files ({len(infolist)})")

    total_declared = sum(i.file_size for i in infolist)
    if total_declared > _MAX_TOTAL_BYTES:
        raise InspectorError(f"Package declared uncompressed size too large ({total_declared} bytes)")

    analysis = PackageAnalysis()
    analysis.package_sha256 = sha256(data).hexdigest()
    analysis.archive_sha256 = sha256(zip_payload).hexdigest()
    analysis.file_count = len(infolist)
    analysis.total_size_bytes = total_declared

    manifest = _load_manifest(zf)
    if manifest:
        _extract_manifest_fields(manifest, analysis)

    js_files = [n for n in zf.namelist() if n.endswith(".js")]
    for name in js_files:
        info = zf.getinfo(name)
        if info.file_size > _MAX_JS_BYTES:
            continue  # skip oversized files
        try:
            with zf.open(name) as f:
                raw = f.read(_MAX_JS_BYTES + 1)
            if len(raw) > _MAX_JS_BYTES:
                continue
            source = raw.decode("utf-8", errors="replace")
        except Exception:  # nosec B112 - best-effort scan: skip unreadable/corrupt entries
            continue
        _analyse_js(source, analysis, name)

    analysis.external_domains = sorted(set(analysis.external_domains))[:_MAX_EXTERNAL_DOMAINS]
    analysis.external_urls = sorted(set(analysis.external_urls))[:_MAX_EXTERNAL_URLS]
    analysis.network_callout_urls = sorted(set(analysis.network_callout_urls))[:_MAX_NETWORK_CALLOUT_URLS]
    analysis.obfuscation_score = min(analysis.obfuscation_score, 10)
    return analysis


def _zip_payload(data: bytes) -> bytes:
    """Return the embedded ZIP payload from a raw ZIP/VSIX or CRX package."""
    if data.startswith(_ZIP_MAGIC):
        return data
    offset = data.find(_ZIP_MAGIC)
    if offset == -1:
        raise InspectorError("Not a valid zip or CRX: no zip signature found")
    return data[offset:]


def _load_manifest(zf: zipfile.ZipFile) -> dict | None:
    """Load manifest.json (Chrome/Edge) or extension/package.json (VS Code)."""
    candidates = ["manifest.json", "extension/package.json", "package.json"]
    for name in candidates:
        if name in zf.namelist():
            try:
                return _read_manifest_json(zf, name)
            except Exception:  # nosec B112 - try the next manifest-name candidate on any read/parse error
                continue
    # Try case-insensitive search
    lower_map = {n.lower(): n for n in zf.namelist()}
    for candidate in candidates:
        if candidate in lower_map:
            try:
                return _read_manifest_json(zf, lower_map[candidate])
            except Exception:  # nosec B112 - try the next manifest-name candidate on any read error
                continue
    return None


def _read_manifest_json(zf: zipfile.ZipFile, name: str) -> dict:
    info = zf.getinfo(name)
    if info.file_size > _MAX_MANIFEST_BYTES:
        raise InspectorError(f"Manifest too large ({info.file_size} bytes)")
    raw = zf.read(name)
    if len(raw) > _MAX_MANIFEST_BYTES:
        raise InspectorError(f"Manifest too large ({len(raw)} bytes)")
    return json.loads(raw.decode("utf-8", errors="replace"))


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

    # VS Code package.json — no traditional permissions model and no Chrome
    # manifest-version semantics.
    is_vscode_package = "contributes" in manifest and "manifest_version" not in manifest
    if is_vscode_package:
        analysis.permissions = []  # VS Code doesn't use Chrome-style permissions
        return

    _analyse_manifest_risks(manifest, analysis)


def _analyse_manifest_risks(manifest: dict, analysis: PackageAnalysis) -> None:
    if analysis.manifest_version < 3:
        _add_finding(
            analysis,
            code="manifest_v2",
            severity="medium",
            title="Manifest V2 extension",
            detail="Manifest V2 has a broader legacy execution model than Manifest V3.",
            source="manifest",
        )

    for pattern in analysis.host_permissions:
        if _is_broad_host_permission(pattern):
            _add_finding(
                analysis,
                code="broad_host_access",
                severity="critical",
                title="Broad host access",
                detail=f"Host permission {pattern!r} allows access across many websites.",
                source="manifest",
            )

    for permission in analysis.permissions:
        if permission in _CRITICAL_PERMISSIONS:
            _add_finding(
                analysis,
                code="high_risk_permission",
                severity="critical",
                title="Critical permission",
                detail=f"Permission {permission!r} can expose sensitive browser capabilities.",
                source="manifest",
            )
        elif permission in _HIGH_PERMISSIONS:
            _add_finding(
                analysis,
                code="high_risk_permission",
                severity="high",
                title="High-risk permission",
                detail=f"Permission {permission!r} can expose sensitive user or browser data.",
                source="manifest",
            )

    for csp_text in _iter_csp_values(manifest.get("content_security_policy")):
        lowered = csp_text.lower()
        if "unsafe-eval" in lowered:
            _add_finding(
                analysis,
                code="csp_unsafe_eval",
                severity="high",
                title="Unsafe CSP allows eval",
                detail="The extension content security policy allows eval-like code execution.",
                source="manifest",
            )
        if "unsafe-inline" in lowered:
            _add_finding(
                analysis,
                code="csp_unsafe_inline",
                severity="medium",
                title="Unsafe CSP allows inline code",
                detail="The extension content security policy allows inline script or style execution.",
                source="manifest",
            )
        if "http://" in lowered:
            _add_finding(
                analysis,
                code="csp_insecure_remote_source",
                severity="high",
                title="Insecure CSP remote source",
                detail="The extension content security policy permits an insecure http:// source.",
                source="manifest",
            )
        if _csp_allows_wildcard_script(lowered):
            _add_finding(
                analysis,
                code="csp_wildcard_script_source",
                severity="medium",
                title="Broad CSP script source",
                detail="The extension content security policy permits a broad script source.",
                source="manifest",
            )


def _analyse_js(source: str, analysis: PackageAnalysis, filename: str) -> None:
    if _EVAL_RE.search(source):
        analysis.uses_eval = True
    _add_js_pattern_finding(
        analysis,
        source,
        filename,
        _EVAL_CALL_RE,
        code="eval_usage",
        severity="high",
        title="eval() usage",
        detail="eval() executes strings as code and can turn data into executable logic.",
    )
    _add_js_pattern_finding(
        analysis,
        source,
        filename,
        _NEW_FUNCTION_RE,
        code="new_function_usage",
        severity="high",
        title="new Function usage",
        detail="new Function() compiles strings as code at runtime.",
    )
    _add_js_pattern_finding(
        analysis,
        source,
        filename,
        _STRING_TIMER_RE,
        code="string_timer_execution",
        severity="medium",
        title="String-based timer execution",
        detail="setTimeout/setInterval with a string argument executes code dynamically.",
    )

    if _REMOTE_FETCH_RE.search(source):
        analysis.uses_remote_code = True
    for pattern, code, title, detail in (
        (_FETCH_REMOTE_RE, "remote_fetch", "Remote fetch call", "JavaScript fetches data from a remote URL."),
        (
            _XHR_REMOTE_RE,
            "remote_xhr",
            "XMLHttpRequest usage",
            "JavaScript uses XMLHttpRequest or opens a remote XHR URL.",
        ),
        (
            _WEBSOCKET_REMOTE_RE,
            "remote_websocket",
            "Remote WebSocket connection",
            "JavaScript opens a WebSocket connection to a remote host.",
        ),
        (
            _EVENTSOURCE_REMOTE_RE,
            "remote_eventsource",
            "Remote EventSource connection",
            "JavaScript opens an EventSource stream to a remote host.",
        ),
        (
            _SENDBEACON_REMOTE_RE,
            "remote_send_beacon",
            "Remote beacon call",
            "JavaScript sends beacon telemetry to a remote URL.",
        ),
    ):
        if pattern.search(source):
            analysis.uses_remote_code = True
            _add_js_pattern_finding(
                analysis,
                source,
                filename,
                pattern,
                code=code,
                severity="medium",
                title=title,
                detail=detail,
            )

    if _IMPORT_SCRIPTS_REMOTE_RE.search(source):
        analysis.uses_remote_code = True
        _add_js_pattern_finding(
            analysis,
            source,
            filename,
            _IMPORT_SCRIPTS_REMOTE_RE,
            code="remote_import_scripts",
            severity="critical",
            title="Remote importScripts()",
            detail="importScripts() loads executable JavaScript from a remote URL.",
        )

    if _DYNAMIC_SCRIPT_RE.search(source):
        severity = "critical" if _REMOTE_SCRIPT_SRC_RE.search(source) else "high"
        detail = (
            "JavaScript dynamically creates a script element with a remote source."
            if severity == "critical"
            else "JavaScript dynamically creates a script element at runtime."
        )
        _add_js_pattern_finding(
            analysis,
            source,
            filename,
            _DYNAMIC_SCRIPT_RE,
            code="dynamic_script_injection",
            severity=severity,
            title="Dynamic script injection",
            detail=detail,
        )

    analysis.network_callout_urls.extend(_extract_network_callout_urls(source))

    # Extract external domains and URLs
    for m in _URL_RE.finditer(source):
        url = _clean_url(m.group(0))
        domain = _domain_from_url(url)
        if not domain:
            continue
        if not _is_safe_domain(domain.removeprefix("www.")):
            analysis.external_urls.append(url)
            analysis.external_domains.append(domain)

    # Minification detection
    lines = source.splitlines()
    if lines:
        long_lines = sum(1 for ln in lines if len(ln) > 500)
        if long_lines > 0 and len(lines) < 20:
            analysis.has_minified_code = True
            _add_finding(
                analysis,
                code="minified_javascript",
                severity="medium",
                title="Minified JavaScript",
                detail="Large compressed JavaScript lines reduce reviewability of the package.",
                source="javascript",
                file=filename,
                line=_first_long_line(lines),
            )

    # Obfuscation heuristic
    score = _obfuscation_score(source)
    if score > analysis.obfuscation_score:
        analysis.obfuscation_score = score
    if score >= 3:
        _add_finding(
            analysis,
            code="obfuscated_javascript",
            severity="high" if score >= 6 else "medium",
            title="Obfuscated JavaScript",
            detail=f"Identifier and escape-sequence heuristics produced an obfuscation score of {score}/10.",
            source="javascript",
            file=filename,
        )


def _is_safe_domain(domain: str) -> bool:
    for safe in _SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return True
    return False


def _extract_network_callout_urls(source: str) -> list[str]:
    urls: list[str] = []
    for pattern in _NETWORK_CALLOUT_URL_PATTERNS:
        for match in pattern.finditer(source):
            url = _clean_url(match.group(1))
            domain = _domain_from_url(url)
            if domain and not _is_safe_domain(domain.removeprefix("www.")):
                urls.append(url)
    return urls


def _clean_url(raw: str) -> str:
    return raw.rstrip(".,;:)]}")


def _obfuscation_score(source: str) -> int:
    score = 0
    identifiers = _IDENTIFIER_RE.findall(source)
    if not identifiers:
        return 0

    total = len(identifiers)
    short = sum(1 for i in identifiers if len(i) <= 2)
    single = sum(1 for i in identifiers if len(i) == 1)

    if total > 50:
        # Check the stronger single-char signal first: every single-char identifier
        # is also a <=2-char (short) one, so `short >= single` always. Testing short
        # first made the single-char branch unreachable (#74); order them so the
        # heavier obfuscation (mostly one-letter names) scores highest.
        if single / total > 0.6:
            score += 4
        elif short / total > 0.6:
            score += 3

    # High ratio of escaped unicode or hex sequences
    unicode_esc = len(re.findall(r"\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}", source))
    if len(source) > 0 and unicode_esc / max(len(source), 1) > 0.05:
        score += 3

    return score


def _add_js_pattern_finding(
    analysis: PackageAnalysis,
    source_text: str,
    filename: str,
    pattern: re.Pattern,
    *,
    code: str,
    severity: str,
    title: str,
    detail: str,
) -> None:
    match = pattern.search(source_text)
    if not match:
        return
    _add_finding(
        analysis,
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        source="javascript",
        file=filename,
        line=_line_number(source_text, match.start()),
    )


def _add_finding(
    analysis: PackageAnalysis,
    *,
    code: str,
    severity: str,
    title: str,
    detail: str,
    source: str,
    file: str | None = None,
    line: int | None = None,
) -> None:
    finding = PackageFinding(
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        source=source,
        file=file,
        line=line,
    )
    key = (finding.code, finding.severity, finding.source, finding.file, finding.line, finding.detail)
    if key not in analysis._finding_keys and len(analysis.findings) < _MAX_FINDINGS:
        analysis._finding_keys.add(key)
        analysis.findings.append(finding)


def _line_number(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _first_long_line(lines: list[str]) -> int | None:
    for idx, line in enumerate(lines, start=1):
        if len(line) > 500:
            return idx
    return None


def _is_broad_host_permission(permission: str) -> bool:
    if permission in _BROAD_HOST_PATTERNS:
        return True
    return permission.startswith("*://") and permission.endswith("/*")


def _iter_csp_values(raw: object) -> list[str]:
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, dict):
        return [str(value) for value in raw.values() if value]
    return []


def _csp_allows_wildcard_script(csp_text: str) -> bool:
    for directive in csp_text.split(";"):
        directive = directive.strip()
        if not directive.startswith(("script-src", "default-src", "worker-src")):
            continue
        parts = directive.split()[1:]
        if "*" in parts or any(part.startswith("https://*") or part.startswith("http://*") for part in parts):
            return True
    return False
