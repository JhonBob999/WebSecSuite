from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse


_ENDPOINT_CATEGORY_ORDER: tuple[str, ...] = (
    "graphql",
    "api",
    "login",
    "auth",
    "admin",
    "php",
    "xhr_hint",
    "route",
    "absolute_url",
    "relative_url",
    "unknown",
)

_JS_ROUTE_QUOTED_RE = re.compile(r"(['\"])((?:https?://|/|\.\.?/)[^'\"\n]{1,512})\1")
_JS_ABSOLUTE_RE = re.compile(r"https?://[^\s'\"<>]{3,1024}", re.IGNORECASE)
_JS_RELATIVE_RE = re.compile(r"(?<![\w:])(?:/|\.\.?/)[^\s'\"<>]{1,512}")
_JS_FETCH_CALL_RE = re.compile(r"\bfetch\s*\(\s*(['\"])([^'\"\n]{1,512})\1", re.IGNORECASE)
_JS_AXIOS_CALL_RE = re.compile(r"\baxios(?:\.[a-z]+)?\s*\(\s*(['\"])([^'\"\n]{1,512})\1", re.IGNORECASE)
_PROTOCOL_RELATIVE_URL_RE = re.compile(r"^//(?P<host>[a-z0-9][a-z0-9.-]*|\[[0-9a-f:.]+\])(?::\d{2,5})?(?:/|$)", re.IGNORECASE)
_HOST_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_ROUTE_EXTENSION_HINTS = (".php", ".json", ".js", ".map", ".txt", ".xml", ".graphql", ".api")
_ROUTE_SIGNAL_HINTS = ("api", "auth", "admin", "login", "upload", "graphql", "file", "path")
_ASSET_FILE_EXTENSIONS = (".js", ".mjs", ".cjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".webp")
_ASSET_SEGMENT_HINTS = ("assets", "asset", "static", "images", "image", "img", "fonts", "font", "vendor", "dist", "build", "chunks")
_ASSET_UTILITY_HINTS = (
    "googletagmanager",
    "google-analytics",
    "doubleclick",
    "recaptcha",
    "analytics",
    "tagmanager",
    "gtm.js",
    "beacon",
    "widget",
    "chat",
    "hotjar",
    "mixpanel",
)
_HTML_TAG_NOISE = {
    "a",
    "body",
    "button",
    "div",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "head",
    "header",
    "html",
    "img",
    "input",
    "li",
    "link",
    "meta",
    "nav",
    "option",
    "p",
    "script",
    "section",
    "span",
    "style",
    "table",
    "tbody",
    "td",
    "textarea",
    "th",
    "thead",
    "tr",
    "ul",
}
_SECRET_HINT_TYPE_ALLOWLIST = {"api_key", "token", "bearer", "client_id", "secret", "authorization", "unknown"}
_SECRET_HINT_ALIAS_TO_TYPE: dict[str, str] = {
    "apikey": "api_key",
    "api_key": "api_key",
    "api-key": "api_key",
    "access_token": "token",
    "accesstoken": "token",
    "auth_token": "token",
    "authtoken": "token",
    "token": "token",
    "bearer": "bearer",
    "clientid": "client_id",
    "client_id": "client_id",
    "client-id": "client_id",
    "secret": "secret",
    "clientsecret": "secret",
    "client_secret": "secret",
    "client-secret": "secret",
    "authorization": "authorization",
}
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|access[_-]?token|auth[_-]?token|token|client[_-]?id|client[_-]?secret|secret|authorization)\b"
    r"\s*[:=]\s*(?P<quote>['\"])(?P<value>(?:\\.|(?!\2).){0,256})\2"
)
_SECRET_HEADER_BEARER_RE = re.compile(
    r"(?i)\b(?:authorization|auth[_-]?header)\b\s*[:=]\s*(?P<quote>['\"])Bearer\s+(?P<value>[A-Za-z0-9._~+/=-]{6,512})\1"
)
_SECRET_STRING_HINT_RE = re.compile(
    r"(?i)(?P<quote>['\"])\s*(?P<key>api[_-]?key|access[_-]?token|auth[_-]?token|token|client[_-]?id|client[_-]?secret|secret|authorization)\s*(?::|=)\s*\1"
)
_SECRET_EVIDENCE_KIND_ALLOWLIST = {"assignment", "object_property", "header_like", "string_pattern"}
_PLACEHOLDER_SECRET_VALUES = {
    "",
    "{}",
    "[]",
    "xxx",
    "test",
    "null",
    "none",
    "undefined",
    "example",
    "token_here",
    "your_api_key",
    "your_token",
    "<redacted>",
    "changeme",
}


def _empty_endpoint_candidate_summary() -> dict[str, int]:
    return {
        "endpoint_candidates_total": 0,
        "endpoint_candidates_unique": 0,
        "endpoint_candidates_api_like": 0,
        "endpoint_candidates_graphql_like": 0,
        "endpoint_candidates_auth_like": 0,
        "endpoint_candidates_login_like": 0,
        "endpoint_candidates_admin_like": 0,
        "endpoint_candidates_php_like": 0,
        "endpoint_candidates_absolute": 0,
        "endpoint_candidates_relative": 0,
        "endpoint_candidates_internal_hint": 0,
        "endpoint_candidates_external_hint": 0,
    }


def _empty_endpoint_linkage_summary() -> dict[str, int | float]:
    return {
        "endpoint_linkage_total": 0,
        "endpoint_linkage_with_candidates": 0,
        "endpoint_linkage_unique_sources": 0,
        "endpoint_linkage_inline_sources": 0,
        "endpoint_linkage_external_sources": 0,
        "endpoint_linkage_internal_sources": 0,
        "endpoint_linkage_multi_candidate_sources": 0,
        "endpoint_linkage_api_sources": 0,
        "endpoint_linkage_graphql_sources": 0,
        "endpoint_linkage_auth_sources": 0,
        "endpoint_linkage_login_sources": 0,
        "endpoint_linkage_admin_sources": 0,
        "endpoint_linkage_php_sources": 0,
        "endpoint_linkage_route_sources": 0,
        "endpoint_linkage_max_candidates_per_source": 0,
        "endpoint_linkage_avg_candidates_per_source": 0.0,
    }


def _empty_secret_hints_summary() -> dict[str, Any]:
    return {
        "total_hints": 0,
        "by_type": {},
        "by_source_kind": {},
        "sources_with_hints": 0,
        "high_confidence_hints": 0,
        "has_api_key_hint": False,
        "has_token_hint": False,
        "has_bearer_hint": False,
        "has_client_id_hint": False,
        "has_secret_hint": False,
        "has_authorization_hint": False,
    }


def _empty_secret_hints_contract() -> dict[str, Any]:
    return {"all": [], "summary": _empty_secret_hints_summary()}


def _normalize_hint_key(raw: str) -> str:
    key = re.sub(r"[^a-z0-9_-]+", "", str(raw or "").strip().lower()).replace("-", "_")
    return key


def _normalize_hint_type(matched_key: str) -> str:
    key = _normalize_hint_key(matched_key)
    hint_type = _SECRET_HINT_ALIAS_TO_TYPE.get(key, "unknown")
    return hint_type if hint_type in _SECRET_HINT_TYPE_ALLOWLIST else "unknown"


def _is_placeholder_like(value: str) -> bool:
    value_clean = str(value or "").strip().strip("'\"").strip().lower()
    if value_clean in _PLACEHOLDER_SECRET_VALUES:
        return True
    if re.fullmatch(r"(?:x|X|\*){3,}", value_clean):
        return True
    if value_clean.startswith("your_") or value_clean.endswith("_here"):
        return True
    return False


def _classify_secret_value_kind(value: str, hint_type: str) -> str:
    value_clean = str(value or "").strip()
    if not value_clean:
        return "empty"
    if value_clean.lower().startswith("bearer "):
        return "bearer_like"
    if value_clean.count(".") == 2 and all(part for part in value_clean.split(".")):
        return "jwt_like"
    value_flat = value_clean.replace("-", "").lower()
    if re.fullmatch(r"[a-f0-9]{16,}", value_flat):
        return "hex_like"
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{16,}", value_clean) and len(value_clean) % 4 == 0:
        return "base64_like"
    if hint_type == "bearer":
        return "bearer_like"
    if re.fullmatch(r"[A-Za-z0-9._~+/=-]{10,}", value_clean):
        return "opaque_string"
    return "literal_string"


def _mask_secret_preview(value: str, value_kind: str) -> str:
    value_clean = str(value or "").strip()
    length = len(value_clean)
    if not value_clean:
        return ""
    if value_kind == "empty":
        return ""
    if value_kind == "jwt_like":
        return f"jwt(len={length})"
    if value_kind == "bearer_like":
        return f"bearer(len={length})"
    if value_kind in {"base64_like", "hex_like", "opaque_string"}:
        if length < 8:
            return ""
        if length > 12:
            return f"opaque(len={length})"
        return f"{value_clean[:3]}***"
    if length > 40:
        return f"opaque(len={length})"
    if length < 4:
        return ""
    if any(ch.isspace() for ch in value_clean):
        return ""
    if length <= 6:
        return f"{value_clean[:2]}***"
    if length <= 12:
        return f"{value_clean[:3]}***"
    return f"{value_clean[:3]}*** (len={length})"


def _should_keep_secret_hint(
    *,
    hint_type: str,
    matched_key: str,
    value: str,
    value_kind: str,
    evidence_kind: str,
    confidence: str,
) -> bool:
    normalized_key = _normalize_hint_key(matched_key)
    if evidence_kind not in _SECRET_EVIDENCE_KIND_ALLOWLIST:
        return False
    if hint_type not in _SECRET_HINT_TYPE_ALLOWLIST:
        return False
    if evidence_kind == "string_pattern":
        return hint_type in {"api_key", "token", "authorization", "secret", "bearer"}
    if value_kind == "empty":
        return False
    value_clean = str(value or "").strip()
    if _is_placeholder_like(value_clean):
        return False
    if len(value_clean) < 4 and value_kind != "bearer_like":
        return False
    if hint_type == "unknown" and confidence == "low":
        return False
    if normalized_key in {"label", "title", "name", "description", "help"}:
        return False
    return True


def _is_comment_line(text: str, index: int) -> bool:
    line_start = text.rfind("\n", 0, max(index, 0)) + 1
    line_end = text.find("\n", max(index, 0))
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].lstrip()
    return line.startswith("//") or line.startswith("/*") or line.startswith("*")


def _guess_evidence_kind(text: str, key_start: int) -> str:
    left_ctx = text[max(0, key_start - 48):key_start]
    if "{" in left_ctx or "," in left_ctx:
        return "object_property"
    return "assignment"


def _safe_confidence(*, hint_type: str, evidence_kind: str, value_kind: str, value: str) -> str:
    value_clean = str(value or "").strip()
    if evidence_kind == "header_like" and value_kind in {"bearer_like", "jwt_like"}:
        return "high"
    if evidence_kind in {"assignment", "object_property"} and hint_type in {"api_key", "token", "client_id", "secret", "authorization"}:
        if len(value_clean) >= 8 and value_kind != "empty" and not _is_placeholder_like(value_clean):
            return "high"
        return "medium"
    if evidence_kind == "string_pattern":
        return "low"
    return "medium"


def _build_secret_hint(
    *,
    hint_type: str,
    source_kind: str,
    source_ref: str,
    matched_key: str,
    value: str,
    evidence_kind: str,
    confidence: str,
) -> dict[str, Any]:
    normalized_type = hint_type if hint_type in _SECRET_HINT_TYPE_ALLOWLIST else "unknown"
    normalized_key = _normalize_hint_key(matched_key)
    normalized_evidence_kind = evidence_kind if evidence_kind in _SECRET_EVIDENCE_KIND_ALLOWLIST else "string_pattern"
    kind = _classify_secret_value_kind(value, normalized_type)
    masked_preview = _mask_secret_preview(value, kind)
    linkage_seed = "|".join(
        [
            normalized_type,
            source_kind,
            source_ref,
            normalized_key,
            normalized_evidence_kind,
        ]
    )
    return {
        "hint_type": normalized_type,
        "source_kind": source_kind,
        "source_ref": source_ref,
        "matched_key": normalized_key,
        "value_kind": kind,
        "value_length": len(str(value or "").strip()),
        "masked_preview": masked_preview,
        "confidence": confidence,
        "evidence_kind": normalized_evidence_kind,
        "linkage_key": hashlib.sha1(linkage_seed.encode("utf-8", errors="replace")).hexdigest()[:16],
    }


def _collect_secret_hints(external_scripts: list[dict[str, Any]], inline_raw_items: list[dict[str, Any]]) -> dict[str, Any]:
    dedupe: dict[tuple[str, str, str, str, str, str], dict[str, Any]] = {}

    def _put(item: dict[str, Any] | None) -> None:
        if not isinstance(item, dict):
            return
        dedupe_key = (
            str(item.get("hint_type") or ""),
            str(item.get("source_kind") or ""),
            str(item.get("source_ref") or ""),
            str(item.get("matched_key") or ""),
            str(item.get("masked_preview") or ""),
            str(item.get("evidence_kind") or ""),
        )
        dedupe[dedupe_key] = item

    def _scan_text(text: str, *, source_kind: str, source_ref: str) -> None:
        if not isinstance(text, str) or not text.strip():
            return
        for match in _SECRET_ASSIGNMENT_RE.finditer(text):
            if _is_comment_line(text, match.start()):
                continue
            key_raw = str(match.group("key") or "").strip()
            value_raw = str(match.group("value") or "")
            value_stripped = value_raw.strip()
            hint_type = _normalize_hint_type(key_raw)
            evidence_kind = _guess_evidence_kind(text, match.start("key"))
            value_kind = _classify_secret_value_kind(value_stripped, hint_type)
            confidence = _safe_confidence(
                hint_type=hint_type,
                evidence_kind=evidence_kind,
                value_kind=value_kind,
                value=value_stripped,
            )
            if not _should_keep_secret_hint(
                hint_type=hint_type,
                matched_key=key_raw,
                value=value_stripped,
                value_kind=value_kind,
                evidence_kind=evidence_kind,
                confidence=confidence,
            ):
                continue
            _put(
                _build_secret_hint(
                    hint_type=hint_type,
                    source_kind=source_kind,
                    source_ref=source_ref,
                    matched_key=key_raw,
                    value=value_stripped,
                    evidence_kind=evidence_kind,
                    confidence=confidence,
                )
            )
        for match in _SECRET_HEADER_BEARER_RE.finditer(text):
            if _is_comment_line(text, match.start()):
                continue
            value_raw = str(match.group("value") or "").strip()
            value_full = f"Bearer {value_raw}" if value_raw else ""
            value_kind = _classify_secret_value_kind(value_full, "bearer")
            confidence = _safe_confidence(
                hint_type="bearer",
                evidence_kind="header_like",
                value_kind=value_kind,
                value=value_full,
            )
            if not _should_keep_secret_hint(
                hint_type="bearer",
                matched_key="authorization",
                value=value_full,
                value_kind=value_kind,
                evidence_kind="header_like",
                confidence=confidence,
            ):
                continue
            _put(
                _build_secret_hint(
                    hint_type="bearer",
                    source_kind=source_kind,
                    source_ref=source_ref,
                    matched_key="authorization",
                    value=value_full,
                    evidence_kind="header_like",
                    confidence=confidence,
                )
            )
        if not any(pattern.search(text) for pattern in (_SECRET_ASSIGNMENT_RE, _SECRET_HEADER_BEARER_RE)):
            for match in _SECRET_STRING_HINT_RE.finditer(text):
                if _is_comment_line(text, match.start()):
                    continue
                key_raw = str(match.group("key") or "").strip()
                hint_type = _normalize_hint_type(key_raw)
                if not _should_keep_secret_hint(
                    hint_type=hint_type,
                    matched_key=key_raw,
                    value="",
                    value_kind="empty",
                    evidence_kind="string_pattern",
                    confidence="low",
                ):
                    continue
                _put(
                    _build_secret_hint(
                        hint_type=hint_type,
                        source_kind=source_kind,
                        source_ref=source_ref,
                        matched_key=key_raw,
                        value="",
                        evidence_kind="string_pattern",
                        confidence="low",
                    )
                )

    for idx, script in enumerate(external_scripts):
        source_ref = str(script.get("absolute_url") or script.get("src") or f"external_js#{idx}")
        for key in ("content", "text", "body", "script_text", "code", "js"):
            content = script.get(key)
            if isinstance(content, str) and content.strip():
                _scan_text(content, source_kind="external_js", source_ref=source_ref)
                break

    for item in inline_raw_items:
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        sha1_value = str(item.get("sha1") or "").strip()
        index_value = item.get("index")
        source_ref = sha1_value or f"inline_js#{index_value if isinstance(index_value, int) else 'unknown'}"
        _scan_text(text, source_kind="inline_js", source_ref=source_ref)

    all_items = sorted(
        dedupe.values(),
        key=lambda item: (
            str(item.get("source_kind") or ""),
            str(item.get("source_ref") or ""),
            str(item.get("hint_type") or ""),
            str(item.get("matched_key") or ""),
            str(item.get("evidence_kind") or ""),
        ),
    )
    summary = _empty_secret_hints_summary()
    summary["total_hints"] = len(all_items)
    summary["high_confidence_hints"] = sum(1 for item in all_items if str(item.get("confidence") or "") == "high")
    summary["sources_with_hints"] = len(
        {(str(item.get("source_kind") or ""), str(item.get("source_ref") or "")) for item in all_items}
    )
    by_type: dict[str, int] = {}
    by_source_kind: dict[str, int] = {}
    for item in all_items:
        hint_type = str(item.get("hint_type") or "unknown")
        source_kind = str(item.get("source_kind") or "unknown")
        by_type[hint_type] = by_type.get(hint_type, 0) + 1
        by_source_kind[source_kind] = by_source_kind.get(source_kind, 0) + 1
    summary["by_type"] = dict(sorted(by_type.items()))
    summary["by_source_kind"] = dict(sorted(by_source_kind.items()))
    summary["has_api_key_hint"] = bool(by_type.get("api_key"))
    summary["has_token_hint"] = bool(by_type.get("token"))
    summary["has_bearer_hint"] = bool(by_type.get("bearer"))
    summary["has_client_id_hint"] = bool(by_type.get("client_id"))
    summary["has_secret_hint"] = bool(by_type.get("secret"))
    summary["has_authorization_hint"] = bool(by_type.get("authorization"))
    return {"all": all_items, "summary": summary}


def _clean_endpoint_candidate_value(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    value = value.strip("'`\" ")
    value = value.strip("()[]{}")
    value = value.strip("\"'`,;")
    value = value.strip()
    return value


def _normalize_endpoint_candidate_value(value: str) -> str:
    cleaned = _clean_endpoint_candidate_value(value)
    return re.sub(r"\s+", "", cleaned.lower())


def _looks_like_asset_path(value: str, normalized_value: str, path: str, host: str = "") -> bool:
    candidate = str(value or "").strip().lower()
    normalized = str(normalized_value or "").strip().lower()
    lowered_path = str(path or "").strip().lower()
    host_value = str(host or "").strip().lower()
    path_only = lowered_path or candidate.split("?", 1)[0].split("#", 1)[0]
    if any(path_only.endswith(ext) for ext in _ASSET_FILE_EXTENSIONS):
        return True
    segments = [segment for segment in path_only.split("/") if segment]
    if any(segment in _ASSET_SEGMENT_HINTS for segment in segments):
        return True
    combined = " ".join(part for part in (candidate, normalized, lowered_path, host_value) if part)
    return any(hint in combined for hint in _ASSET_UTILITY_HINTS)


def _collect_category_signals(value: str, normalized_value: str, path: str, host: str, evidence: str, source_kind: str) -> dict[str, bool]:
    lowered_path = str(path or "").lower()
    lowered_value = str(value or "").lower()
    lowered_normalized = str(normalized_value or "").lower()
    lowered_host = str(host or "").lower()
    lowered_evidence = str(evidence or "").lower()
    lowered_source_kind = str(source_kind or "").lower()
    haystack = " ".join(
        part
        for part in (lowered_value, lowered_normalized, lowered_path, lowered_host, lowered_evidence, lowered_source_kind)
        if part
    )
    graphql = bool(re.search(r"(^|[/_.-])graphql(?:$|[/_.?-])", lowered_path or lowered_normalized or lowered_value))
    api = bool(re.search(r"(^|/)api(?:/|$|\?)", lowered_path or lowered_normalized or lowered_value) or "/v1/" in haystack or "/v2/" in haystack or "/v3/" in haystack)
    login = any(token in haystack for token in ("/login", "signin", "sign-in", "logout", "log-in", "/logon", "/signout", "sign-out"))
    auth = any(token in haystack for token in ("/auth", "register", "signup", "sign-up", "session", "reset", "password", "oauth", "token"))
    admin = any(token in haystack for token in ("/admin", "/backend", "dashboard", "controlpanel", "cpanel", "/root"))
    php = ".php" in (lowered_path or lowered_normalized or lowered_value)
    xhr = any(token in haystack for token in ("fetch", "axios", "xmlhttprequest"))
    return {
        "graphql": graphql,
        "api": api,
        "login": login,
        "auth": auth,
        "admin": admin,
        "php": php,
        "xhr_hint": xhr,
    }


def _classify_path_category(value: str, normalized_value: str, path: str) -> str:
    if value.startswith(("http://", "https://")):
        return "absolute_url"
    if value.startswith(("/", "./", "../")):
        return "relative_url"
    if _looks_like_meaningful_route(path or value, normalized_value):
        return "route"
    return "unknown"


def _classify_endpoint_candidate(value: str, normalized_value: str, path: str, host: str, evidence: str, source_kind: str, force_category: str = "") -> str:
    signals = _collect_category_signals(value, normalized_value, path, host, evidence, source_kind)
    fallback_category = _classify_path_category(value, normalized_value, path)
    asset_like = _looks_like_asset_path(value, normalized_value, path, host)
    if force_category == "xhr_hint":
        signals["xhr_hint"] = True
    if asset_like:
        if fallback_category in {"route", "absolute_url", "relative_url"}:
            return fallback_category
        return "unknown"
    if not asset_like:
        if signals["graphql"]:
            return "graphql"
        if signals["api"]:
            return "api"
        if signals["login"]:
            return "login"
        if signals["auth"]:
            return "auth"
        if signals["admin"]:
            return "admin"
        if signals["php"]:
            return "php"
    if signals["xhr_hint"]:
        return "xhr_hint"
    if fallback_category in {"route", "absolute_url", "relative_url"}:
        return fallback_category
    return "unknown"


def _looks_like_protocol_relative_url(value: str) -> bool:
    candidate = str(value or "").strip()
    if not candidate.startswith("//"):
        return False
    match = _PROTOCOL_RELATIVE_URL_RE.match(candidate)
    if not match:
        return False
    host = (match.group("host") or "").lower().strip("[]")
    return bool(host and ("." in host or host == "localhost" or bool(_HOST_IPV4_RE.match(host))))


def _is_html_tag_like_fragment(value: str) -> bool:
    candidate = str(value or "").strip().split("?", 1)[0].split("#", 1)[0]
    if not candidate:
        return False
    while candidate.startswith("../"):
        candidate = candidate[3:]
    if candidate.startswith("./"):
        candidate = candidate[2:]
    candidate = candidate.lstrip("/")
    if not candidate:
        return False
    first_segment = candidate.split("/", 1)[0].strip().strip(":").lower()
    return bool(first_segment and first_segment in _HTML_TAG_NOISE)


def _looks_like_meaningful_route(value: str, lowered: str) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return False
    if _looks_like_protocol_relative_url(candidate):
        return True
    if "?" in candidate or "#" in candidate:
        return True
    path_candidate = candidate.split("?", 1)[0].split("#", 1)[0].lower()
    if any(path_candidate.endswith(ext) for ext in _ROUTE_EXTENSION_HINTS):
        return True
    if any(signal in lowered for signal in _ROUTE_SIGNAL_HINTS):
        return True
    stripped = path_candidate
    while stripped.startswith("../"):
        stripped = stripped[3:]
    if stripped.startswith("./"):
        stripped = stripped[2:]
    segments = [segment for segment in stripped.split("/") if segment]
    return len(segments) >= 2


def _looks_like_noise_relative_candidate(value: str, lowered: str) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return True
    if candidate in {"//", "/*", "*/"}:
        return True
    if candidate.startswith(("/*", "*/")):
        return True
    if candidate.startswith("//") and not _looks_like_protocol_relative_url(candidate):
        return True
    if candidate.endswith(":") and "/" not in candidate.replace("//", "/", 1):
        return True
    if len(candidate) <= 2:
        return True
    if _is_html_tag_like_fragment(candidate):
        return True
    if re.fullmatch(r"(?:/|\./|\.\./)?[a-z_$][\w$-]*:?", lowered) and not any(signal in lowered for signal in _ROUTE_SIGNAL_HINTS):
        return True
    return not _looks_like_meaningful_route(candidate, lowered)


def _should_filter_endpoint_candidate(candidate: dict[str, Any]) -> bool:
    category = str(candidate.get("category") or "")
    value = str(candidate.get("value") or "")
    lowered = str(candidate.get("normalized_value") or "")
    if not value or not lowered:
        return True
    if category not in {"relative_url", "route"} and not bool(candidate.get("is_relative")):
        return False
    return _looks_like_noise_relative_candidate(value, lowered)


def _candidate_sort_key(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    category = str(item.get("category") or "unknown")
    category_order = _ENDPOINT_CATEGORY_ORDER.index(category) if category in _ENDPOINT_CATEGORY_ORDER else len(_ENDPOINT_CATEGORY_ORDER)
    return (
        f"{category_order:02d}",
        str(item.get("normalized_value") or ""),
        str(item.get("source_kind") or ""),
        str(item.get("source_ref") or ""),
        str(item.get("evidence") or ""),
    )


def _build_endpoint_candidate(
    raw_value: str,
    source_kind: str,
    source_ref: str,
    base_host: str,
    evidence: str,
    force_category: str = "",
) -> dict[str, Any] | None:
    value = _clean_endpoint_candidate_value(raw_value)
    normalized_value = _normalize_endpoint_candidate_value(value)
    if not value or not normalized_value:
        return None
    parse_target = value if value.startswith(("http://", "https://", "/", "./", "../")) else ""
    parsed = urlparse(parse_target)
    is_absolute = value.startswith(("http://", "https://"))
    is_relative = value.startswith(("/", "./", "../"))
    host = (parsed.hostname or parsed.netloc or "").lower() if parsed else ""
    path = parsed.path or ""
    category = _classify_endpoint_candidate(value, normalized_value, path, host, evidence, source_kind, force_category=force_category)
    internal_hint = bool(base_host and host and host == base_host)
    external_hint = bool(host and base_host and host != base_host)
    dedupe_key = f"{normalized_value}|{category}"
    confidence = "medium" if category in {"api", "graphql", "auth", "login", "admin", "php", "absolute_url", "relative_url", "xhr_hint"} else "low"
    return {
        "value": value,
        "normalized_value": normalized_value,
        "source_kind": str(source_kind or "other existing passive source"),
        "source_ref": str(source_ref or ""),
        "category": category,
        "is_absolute": is_absolute,
        "is_relative": is_relative,
        "host": host,
        "path": path,
        "internal_hint": internal_hint,
        "external_hint": external_hint,
        "evidence": str(evidence or "passive_js_pattern"),
        "confidence": confidence,
        "dedupe_key": dedupe_key,
    }


def _collect_endpoint_candidates(
    *,
    base_host: str,
    source_page_url: str,
    external_scripts: list[dict[str, Any]],
    inline_raw_items: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    candidates_by_key: dict[str, dict[str, Any]] = {}
    raw_total = 0

    def _put(candidate: dict[str, Any] | None) -> None:
        nonlocal raw_total
        if not candidate:
            return
        if _should_filter_endpoint_candidate(candidate):
            return
        raw_total += 1
        key = str(candidate.get("dedupe_key") or "")
        if not key or key in candidates_by_key:
            return
        candidates_by_key[key] = candidate

    for item in external_scripts:
        src = str(item.get("src") or "")
        absolute_url = str(item.get("absolute_url") or "")
        source_ref = absolute_url or src
        _put(_build_endpoint_candidate(src, "script_src", source_ref, base_host, "script_src"))
        if absolute_url and absolute_url != src:
            _put(_build_endpoint_candidate(absolute_url, "external_js", source_ref, base_host, "external_js_absolute"))

    for inline_item in inline_raw_items:
        text = str(inline_item.get("text") or "")
        idx = int(inline_item.get("index") or 0)
        inline_sha1 = str(inline_item.get("sha1") or "").strip()
        if not text.strip():
            continue
        source_ref = inline_sha1 or source_page_url or f"inline_script_{idx}"
        _put(_build_endpoint_candidate("fetch(...)", "inline_js", source_ref, base_host, "fetch_call_hint", force_category="xhr_hint") if re.search(r"\bfetch\s*\(", text, re.IGNORECASE) else None)
        _put(_build_endpoint_candidate("axios(...)", "inline_js", source_ref, base_host, "axios_call_hint", force_category="xhr_hint") if re.search(r"\baxios(?:\.[a-z]+)?\s*\(", text, re.IGNORECASE) else None)
        _put(
            _build_endpoint_candidate("XMLHttpRequest", "inline_js", source_ref, base_host, "xmlhttprequest_hint", force_category="xhr_hint")
            if re.search(r"\bXMLHttpRequest\b", text)
            else None
        )
        for match in _JS_FETCH_CALL_RE.finditer(text):
            _put(_build_endpoint_candidate(match.group(2), "inline_js", source_ref, base_host, "fetch_argument"))
        for match in _JS_AXIOS_CALL_RE.finditer(text):
            _put(_build_endpoint_candidate(match.group(2), "inline_js", source_ref, base_host, "axios_argument"))
        for match in _JS_ABSOLUTE_RE.finditer(text):
            _put(_build_endpoint_candidate(match.group(0), "inline_js", source_ref, base_host, "absolute_url_literal", force_category="absolute_url"))
        for match in _JS_RELATIVE_RE.finditer(text):
            _put(_build_endpoint_candidate(match.group(0), "inline_js", source_ref, base_host, "relative_path_literal", force_category="relative_url"))
        for match in _JS_ROUTE_QUOTED_RE.finditer(text):
            _put(_build_endpoint_candidate(match.group(2), "inline_js", source_ref, base_host, "quoted_route_literal"))

    endpoint_candidates = sorted(candidates_by_key.values(), key=_candidate_sort_key)
    summary = _empty_endpoint_candidate_summary()
    summary["endpoint_candidates_total"] = raw_total
    summary["endpoint_candidates_unique"] = len(endpoint_candidates)
    for item in endpoint_candidates:
        category = str(item.get("category") or "")
        if category == "api":
            summary["endpoint_candidates_api_like"] += 1
        if category == "graphql":
            summary["endpoint_candidates_graphql_like"] += 1
        if category == "auth":
            summary["endpoint_candidates_auth_like"] += 1
        if category == "login":
            summary["endpoint_candidates_login_like"] += 1
        if category == "admin":
            summary["endpoint_candidates_admin_like"] += 1
        if category == "php":
            summary["endpoint_candidates_php_like"] += 1
        if bool(item.get("is_absolute")):
            summary["endpoint_candidates_absolute"] += 1
        if bool(item.get("is_relative")):
            summary["endpoint_candidates_relative"] += 1
        if bool(item.get("internal_hint")):
            summary["endpoint_candidates_internal_hint"] += 1
        if bool(item.get("external_hint")):
            summary["endpoint_candidates_external_hint"] += 1
    return endpoint_candidates, summary


def _build_endpoint_linkage(
    *,
    endpoint_candidates: list[dict[str, Any]],
    external_scripts: list[dict[str, Any]],
    inline_scripts: list[dict[str, Any]],
    page_sources: list[dict[str, Any]],
    base_host: str,
) -> tuple[list[dict[str, Any]], dict[str, int | float]]:
    source_meta: dict[tuple[str, str], dict[str, str]] = {}
    for script in external_scripts:
        src = str(script.get("src") or "").strip()
        absolute_url = str(script.get("absolute_url") or "").strip()
        source_ref = absolute_url or src
        if not source_ref:
            continue
        common_meta = {
            "source_page_url": str(script.get("source_page_url") or ""),
            "source_page_host": str(script.get("source_page_host") or ""),
            "source_page_path": str(script.get("source_page_path") or ""),
        }
        source_meta[("script_src", source_ref)] = {"source_label": src or absolute_url, **common_meta}
        source_meta[("external_js", source_ref)] = {"source_label": absolute_url or src, **common_meta}
    for inline in inline_scripts:
        sha1_value = str(inline.get("sha1") or "").strip()
        if not sha1_value:
            continue
        source_meta[("inline_js", sha1_value)] = {
            "source_page_url": str(inline.get("source_page_url") or ""),
            "source_page_host": str(inline.get("source_page_host") or ""),
            "source_page_path": str(inline.get("source_page_path") or ""),
            "source_label": f"inline:{sha1_value[:12]}",
        }
    for page in page_sources:
        page_url = str(page.get("page_url") or "").strip()
        if not page_url:
            continue
        source_meta[("other existing passive source", page_url)] = {
            "source_page_url": page_url,
            "source_page_host": str(page.get("page_host") or ""),
            "source_page_path": str(page.get("page_path") or ""),
            "source_label": page_url,
        }

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for candidate in endpoint_candidates:
        source_kind = str(candidate.get("source_kind") or "other existing passive source")
        source_ref = str(candidate.get("source_ref") or "")
        if not source_ref:
            source_ref = str(candidate.get("source_page_url") or "")
        grouped.setdefault((source_kind, source_ref), []).append(candidate)

    linkage_items: list[dict[str, Any]] = []
    for source_kind, source_ref in sorted(grouped.keys(), key=lambda item: (item[0], item[1])):
        candidates = grouped.get((source_kind, source_ref), [])
        meta = source_meta.get((source_kind, source_ref), {})
        source_page_url = str(meta.get("source_page_url") or "")
        source_page_host = str(meta.get("source_page_host") or "")
        source_page_path = str(meta.get("source_page_path") or "")
        if not source_page_url and page_sources:
            source_page_url = str(page_sources[0].get("page_url") or "")
            source_page_host = source_page_host or str(page_sources[0].get("page_host") or "")
            source_page_path = source_page_path or str(page_sources[0].get("page_path") or "")
        source_label = str(meta.get("source_label") or "") or source_ref[:120]

        seen_values: set[str] = set()
        candidate_values: list[str] = []
        categories_present: list[str] = []
        category_counts: dict[str, int] = {}
        internal_hint_count = 0
        external_hint_count = 0
        for item in sorted(candidates, key=_candidate_sort_key):
            normalized_value = str(item.get("normalized_value") or "")
            candidate_value = str(item.get("value") or "")
            if normalized_value and normalized_value not in seen_values:
                seen_values.add(normalized_value)
                candidate_values.append((candidate_value or normalized_value)[:180])
            category = str(item.get("category") or "")
            if category and category not in categories_present:
                categories_present.append(category)
            category_counts[category] = category_counts.get(category, 0) + 1
            if bool(item.get("internal_hint")):
                internal_hint_count += 1
            if bool(item.get("external_hint")):
                external_hint_count += 1

        top_category = ""
        if category_counts:
            top_category = sorted(
                category_counts.items(),
                key=lambda kv: (-kv[1], _ENDPOINT_CATEGORY_ORDER.index(kv[0]) if kv[0] in _ENDPOINT_CATEGORY_ORDER else len(_ENDPOINT_CATEGORY_ORDER), kv[0]),
            )[0][0]
        linkage_key_raw = f"{source_kind}|{source_ref}|{source_page_url}"
        linkage_key = hashlib.sha1(linkage_key_raw.encode("utf-8", errors="replace")).hexdigest()[:16]
        linkage_items.append(
            {
                "source_kind": source_kind,
                "source_ref": source_ref,
                "source_page_url": source_page_url,
                "source_page_host": source_page_host,
                "source_page_path": source_page_path,
                "source_label": source_label,
                "candidate_values": candidate_values,
                "candidate_count": len(candidates),
                "unique_candidate_count": len(candidate_values),
                "categories_present": categories_present,
                "internal_hint_count": internal_hint_count,
                "external_hint_count": external_hint_count,
                "api_like_count": category_counts.get("api", 0),
                "graphql_like_count": category_counts.get("graphql", 0),
                "auth_like_count": category_counts.get("auth", 0),
                "login_like_count": category_counts.get("login", 0),
                "admin_like_count": category_counts.get("admin", 0),
                "php_like_count": category_counts.get("php", 0),
                "route_like_count": category_counts.get("route", 0) + category_counts.get("relative_url", 0) + category_counts.get("absolute_url", 0),
                "top_category": top_category,
                "linkage_key": linkage_key,
            }
        )

    summary = _empty_endpoint_linkage_summary()
    summary["endpoint_linkage_total"] = len(linkage_items)
    summary["endpoint_linkage_with_candidates"] = sum(1 for item in linkage_items if int(item.get("candidate_count") or 0) > 0)
    summary["endpoint_linkage_unique_sources"] = len({(str(item.get("source_kind") or ""), str(item.get("source_ref") or "")) for item in linkage_items})
    summary["endpoint_linkage_inline_sources"] = sum(1 for item in linkage_items if str(item.get("source_kind") or "") == "inline_js")
    summary["endpoint_linkage_external_sources"] = sum(1 for item in linkage_items if str(item.get("source_kind") or "") in {"script_src", "external_js"})
    summary["endpoint_linkage_internal_sources"] = sum(1 for item in linkage_items if str(item.get("source_page_host") or "").lower() == (base_host or ""))
    summary["endpoint_linkage_multi_candidate_sources"] = sum(1 for item in linkage_items if int(item.get("unique_candidate_count") or 0) > 1)
    summary["endpoint_linkage_api_sources"] = sum(1 for item in linkage_items if int(item.get("api_like_count") or 0) > 0)
    summary["endpoint_linkage_graphql_sources"] = sum(1 for item in linkage_items if int(item.get("graphql_like_count") or 0) > 0)
    summary["endpoint_linkage_auth_sources"] = sum(1 for item in linkage_items if int(item.get("auth_like_count") or 0) > 0)
    summary["endpoint_linkage_login_sources"] = sum(1 for item in linkage_items if int(item.get("login_like_count") or 0) > 0)
    summary["endpoint_linkage_admin_sources"] = sum(1 for item in linkage_items if int(item.get("admin_like_count") or 0) > 0)
    summary["endpoint_linkage_php_sources"] = sum(1 for item in linkage_items if int(item.get("php_like_count") or 0) > 0)
    summary["endpoint_linkage_route_sources"] = sum(1 for item in linkage_items if int(item.get("route_like_count") or 0) > 0)
    summary["endpoint_linkage_max_candidates_per_source"] = max((int(item.get("unique_candidate_count") or 0) for item in linkage_items), default=0)
    summary["endpoint_linkage_avg_candidates_per_source"] = (
        float(sum(int(item.get("unique_candidate_count") or 0) for item in linkage_items) / len(linkage_items)) if linkage_items else 0.0
    )
    return linkage_items, summary


def empty_js_recon_contract() -> dict[str, Any]:
    return {
        "external_scripts": [],
        "inline_scripts": [],
        "endpoint_candidates": [],
        "endpoint_linkage": [],
        "secret_hints": _empty_secret_hints_contract(),
        "page_sources": [],
        "summary": {
            "external_total": 0,
            "inline_total": 0,
            "internal_external_scripts": 0,
            "third_party_external_scripts": 0,
            "module_scripts": 0,
            "async_scripts": 0,
            "defer_scripts": 0,
            "integrity_scripts": 0,
            "inline_nonempty_total": 0,
            "minified_external_scripts": 0,
            "module_external_scripts": 0,
            "blocking_external_scripts": 0,
            "library_hinted_external_scripts": 0,
            "version_hinted_external_scripts": 0,
            "external_with_query_params": 0,
            "inline_module_scripts": 0,
            "inline_json_like_scripts": 0,
            "inline_importmap_scripts": 0,
            "inline_with_close_guard": 0,
            "page_sources_total": 0,
            "external_scripts_with_page_link": 0,
            "inline_scripts_with_page_link": 0,
            "multi_page_script_links": 0,
            "unique_external_hosts": 0,
            "unique_source_page_hosts": 0,
            "internal_page_sources": 0,
            "external_page_sources": 0,
            "pages_with_inline_scripts": 0,
            "pages_with_external_scripts": 0,
            "max_external_scripts_on_page": 0,
            "max_inline_scripts_on_page": 0,
            "avg_external_scripts_per_page": 0.0,
            "avg_inline_scripts_per_page": 0.0,
            **_empty_endpoint_candidate_summary(),
            **_empty_endpoint_linkage_summary(),
        },
        "coverage": {
            "external_scripts_linked_ratio": 0.0,
            "inline_scripts_linked_ratio": 0.0,
            "page_sources_complete": True,
            "linkage_mode": "single_page_passive",
        },
    }


def _normalize_script_attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in attrs:
        if key is None:
            continue
        out[str(key).strip().lower()] = "" if value is None else str(value)
    return out


def _bool_attr(attrs: dict[str, str], name: str) -> bool:
    return name in attrs


def _script_flags(attrs: dict[str, str]) -> dict[str, bool]:
    type_value = (attrs.get("type") or "").strip().lower()
    return {
        "async": _bool_attr(attrs, "async"),
        "defer": _bool_attr(attrs, "defer"),
        "module": type_value == "module",
        "nomodule": _bool_attr(attrs, "nomodule"),
        "integrity_present": bool((attrs.get("integrity") or "").strip()),
        "crossorigin_present": bool((attrs.get("crossorigin") or "").strip()),
    }


def _build_preview(text: str, max_chars: int = 180) -> str:
    if not isinstance(text, str):
        return ""
    collapsed = " ".join(text.strip().split())
    if len(collapsed) <= max_chars:
        return collapsed
    return collapsed[: max_chars - 1] + "…"


def _derive_script_kind(type_value: str) -> str:
    value = (type_value or "").strip().lower()
    if not value:
        return "classic"
    if value == "module":
        return "module"
    if value == "importmap":
        return "importmap"
    if "json" in value:
        return "json"
    if value in {"text/javascript", "application/javascript", "application/ecmascript", "text/ecmascript"}:
        return "classic"
    return "other"


def _derive_load_hint(async_flag: bool, defer_flag: bool) -> str:
    if async_flag and defer_flag:
        return "other"
    if async_flag:
        return "async"
    if defer_flag:
        return "defer"
    return "blocking"


def _extract_version_hint(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"(\d+(?:\.\d+){1,3})", text)
    return match.group(1) if match else ""


def _library_and_version_hint(src: str, path: str, filename: str) -> tuple[str, str]:
    candidate = " ".join([filename or "", path or "", src or ""]).lower()
    patterns: list[tuple[str, str]] = [
        ("react-dom", r"react[-_.]?dom(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("jquery", r"jquery(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("react", r"react(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("angular", r"angular(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("axios", r"axios(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("alpine", r"alpine(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("vue", r"vue(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("bootstrap", r"bootstrap(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("lodash", r"lodash(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("gsap", r"gsap(?:[-_.]?v?([\d][\w.\-]*))?"),
        ("typed", r"typed(?:[-_.]?v?([\d][\w.\-]*))?"),
    ]
    for library_name, pattern in patterns:
        match = re.search(pattern, candidate)
        if not match:
            continue
        version_raw = (match.group(1) or "").strip("._-")
        version_hint = _extract_version_hint(version_raw)
        return library_name, version_hint
    return "", ""


def _contains_html_close_guard(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in ("<\\/script", "<\\\\/script", "<\\x2fscript"))


class _ScriptSourceHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.external: list[dict[str, Any]] = []
        self.inline_items: list[dict[str, Any]] = []
        self._in_inline_script = False
        self._inline_chunks: list[str] = []
        self._inline_attrs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if str(tag).lower() != "script":
            return
        script_attrs = _normalize_script_attrs(attrs)
        src_raw = (script_attrs.get("src") or "").strip()
        if src_raw:
            self.external.append({"src": src_raw, "attrs": script_attrs})
            self._in_inline_script = False
            self._inline_chunks = []
            self._inline_attrs = {}
            return
        self._in_inline_script = True
        self._inline_chunks = []
        self._inline_attrs = script_attrs

    def handle_data(self, data: str) -> None:
        if self._in_inline_script and isinstance(data, str):
            self._inline_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if str(tag).lower() != "script":
            return
        if self._in_inline_script:
            self.inline_items.append({"text": "".join(self._inline_chunks), "attrs": dict(self._inline_attrs)})
        self._in_inline_script = False
        self._inline_chunks = []
        self._inline_attrs = {}


def collect_js_sources(html: str, base_url: str) -> dict[str, Any]:
    contract = empty_js_recon_contract()
    if not isinstance(html, str) or not html:
        return contract

    parser = _ScriptSourceHTMLParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return contract

    source_parsed = urlparse(base_url or "")
    source_page_url = str(base_url or "").strip()
    source_page_host = (source_parsed.hostname or source_parsed.netloc or "").lower()
    source_page_path = source_parsed.path or "/"
    base_host = source_page_host
    external_scripts: list[dict[str, Any]] = []
    seen_abs: set[str] = set()
    internal_total = 0
    module_total = 0
    async_total = 0
    defer_total = 0
    integrity_total = 0
    minified_external_total = 0
    module_external_total = 0
    blocking_external_total = 0
    library_hinted_total = 0
    version_hinted_total = 0
    external_with_query_params_total = 0

    for item in parser.external:
        src = str(item.get("src") or "").strip()
        attrs = item.get("attrs") if isinstance(item.get("attrs"), dict) else {}
        if not src:
            continue
        try:
            absolute_url = urljoin(base_url or "", src)
        except Exception:
            absolute_url = src
        abs_key = absolute_url or src
        if abs_key in seen_abs:
            continue
        seen_abs.add(abs_key)

        parsed = urlparse(absolute_url or "")
        host = (parsed.hostname or parsed.netloc or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        is_internal = bool(base_host and host and host == base_host)
        flags = _script_flags(attrs)
        type_value = (attrs.get("type") or "").strip().lower()
        script_kind = _derive_script_kind(type_value)
        load_hint = _derive_load_hint(flags["async"], flags["defer"])
        filename = path.rsplit("/", 1)[-1] if path else ""
        extension = ""
        if filename and "." in filename and not filename.endswith("."):
            extension = "." + filename.rsplit(".", 1)[-1].lower()
        is_minified_hint = bool(re.search(r"\.min\.(?:js|mjs)(?:$|\?)", filename.lower() or path.lower()))
        library_hint, version_hint = _library_and_version_hint(src, path, filename)
        query_param_names = sorted({name for name, _ in parse_qsl(query, keep_blank_values=True) if name})
        query_params_count = len(query_param_names)

        if is_internal:
            internal_total += 1
        if flags["module"]:
            module_total += 1
            module_external_total += 1
        if flags["async"]:
            async_total += 1
        if flags["defer"]:
            defer_total += 1
        if flags["integrity_present"]:
            integrity_total += 1
        if is_minified_hint:
            minified_external_total += 1
        if load_hint == "blocking":
            blocking_external_total += 1
        if library_hint:
            library_hinted_total += 1
        if version_hint:
            version_hinted_total += 1
        if query_params_count > 0:
            external_with_query_params_total += 1

        external_scripts.append(
            {
                "src": src,
                "absolute_url": absolute_url,
                "host": host,
                "path": path,
                "query": query,
                "is_internal": is_internal,
                "type_hint": "javascript",
                "filename": filename,
                "extension": extension,
                "is_minified_hint": is_minified_hint,
                "script_kind": script_kind,
                "load_hint": load_hint,
                "library_hint": library_hint,
                "version_hint": version_hint,
                "query_param_names": query_param_names,
                "query_params_count": query_params_count,
                "attrs": flags,
                "source_page_url": source_page_url,
                "source_page_host": source_page_host,
                "source_page_path": source_page_path,
                "seen_on_pages": [source_page_url] if source_page_url else [],
                "seen_on_count": 1 if source_page_url else 0,
            }
        )

    inline_scripts: list[dict[str, Any]] = []
    inline_raw_items: list[dict[str, Any]] = []
    inline_nonempty_total = 0
    inline_module_total = 0
    inline_json_like_total = 0
    inline_importmap_total = 0
    inline_with_close_guard_total = 0
    for idx, inline_item in enumerate(parser.inline_items):
        text = inline_item.get("text") if isinstance(inline_item, dict) else ""
        attrs = inline_item.get("attrs") if isinstance(inline_item, dict) and isinstance(inline_item.get("attrs"), dict) else {}
        text = text if isinstance(text, str) else ""
        stripped = text.strip()
        type_value = (attrs.get("type") or "").strip().lower()
        script_kind = _derive_script_kind(type_value)
        nonempty = bool(stripped)
        contains_html_close_guard = _contains_html_close_guard(text)

        if stripped:
            inline_nonempty_total += 1
        if script_kind == "module":
            inline_module_total += 1
        if script_kind == "json":
            inline_json_like_total += 1
        if script_kind == "importmap":
            inline_importmap_total += 1
        if contains_html_close_guard:
            inline_with_close_guard_total += 1

        statement_hint = "code"
        if script_kind == "importmap":
            statement_hint = "importmap"
        elif script_kind == "json":
            statement_hint = "json_like"
        elif script_kind == "other":
            statement_hint = "unknown"

        inline_scripts.append(
            {
                "index": idx,
                "chars": len(text),
                "sha1": hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest(),
                "preview": _build_preview(text),
                "script_kind": script_kind,
                "nonempty": nonempty,
                "statement_hint": statement_hint,
                "contains_html_close_guard": contains_html_close_guard,
                "source_page_url": source_page_url,
                "source_page_host": source_page_host,
                "source_page_path": source_page_path,
            }
        )
        inline_raw_items.append({"index": idx, "text": text, "sha1": hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()})

    external_total = len(external_scripts)
    external_script_urls = sorted({str(item.get("absolute_url") or "").strip() for item in external_scripts if str(item.get("absolute_url") or "").strip()})
    inline_script_sha1: list[str] = []
    seen_inline_sha1: set[str] = set()
    for inline_item in inline_scripts:
        sha1_value = str(inline_item.get("sha1") or "").strip()
        if not sha1_value or sha1_value in seen_inline_sha1:
            continue
        seen_inline_sha1.add(sha1_value)
        inline_script_sha1.append(sha1_value)
    page_sources: list[dict[str, Any]] = [
        {
            "page_url": source_page_url,
            "page_host": source_page_host,
            "page_path": source_page_path,
            "external_scripts_total": external_total,
            "inline_scripts_total": len(inline_scripts),
            "external_script_urls": external_script_urls,
            "inline_script_sha1": inline_script_sha1,
        }
    ]
    external_with_page_link_total = sum(
        1 for item in external_scripts if str(item.get("source_page_url") or "").strip() and int(item.get("seen_on_count") or 0) > 0
    )
    inline_with_page_link_total = sum(1 for item in inline_scripts if str(item.get("source_page_url") or "").strip())
    multi_page_script_links = sum(1 for item in external_scripts if int(item.get("seen_on_count") or 0) > 1)
    unique_external_hosts = len({str(item.get("host") or "").strip().lower() for item in external_scripts if str(item.get("host") or "").strip()})
    unique_source_page_hosts = len(
        {
            str(item.get("page_host") or item.get("source_page_host") or "").strip().lower()
            for item in page_sources
            if str(item.get("page_host") or item.get("source_page_host") or "").strip()
        }
    )
    internal_page_sources = sum(
        1
        for item in page_sources
        if str(item.get("page_host") or item.get("source_page_host") or "").strip().lower() == (base_host or "")
    )
    external_page_sources = max(0, len(page_sources) - internal_page_sources)
    pages_with_inline_scripts = sum(1 for item in page_sources if int(item.get("inline_scripts_total") or 0) > 0)
    pages_with_external_scripts = sum(1 for item in page_sources if int(item.get("external_scripts_total") or 0) > 0)
    max_external_scripts_on_page = max((int(item.get("external_scripts_total") or 0) for item in page_sources), default=0)
    max_inline_scripts_on_page = max((int(item.get("inline_scripts_total") or 0) for item in page_sources), default=0)
    page_sources_total = len(page_sources)
    avg_external_scripts_per_page = float(external_total / page_sources_total) if page_sources_total > 0 else 0.0
    avg_inline_scripts_per_page = float(len(inline_scripts) / page_sources_total) if page_sources_total > 0 else 0.0
    endpoint_candidates, endpoint_summary = _collect_endpoint_candidates(
        base_host=base_host,
        source_page_url=source_page_url,
        external_scripts=external_scripts,
        inline_raw_items=inline_raw_items,
    )
    endpoint_linkage, endpoint_linkage_summary = _build_endpoint_linkage(
        endpoint_candidates=endpoint_candidates,
        external_scripts=external_scripts,
        inline_scripts=inline_scripts,
        page_sources=page_sources,
        base_host=base_host,
    )
    secret_hints = _collect_secret_hints(
        external_scripts=external_scripts,
        inline_raw_items=inline_raw_items,
    )
    summary = {
        "external_total": external_total,
        "inline_total": len(inline_scripts),
        "internal_external_scripts": internal_total,
        "third_party_external_scripts": max(0, external_total - internal_total),
        "module_scripts": module_total,
        "async_scripts": async_total,
        "defer_scripts": defer_total,
        "integrity_scripts": integrity_total,
        "inline_nonempty_total": inline_nonempty_total,
        "minified_external_scripts": minified_external_total,
        "module_external_scripts": module_external_total,
        "blocking_external_scripts": blocking_external_total,
        "library_hinted_external_scripts": library_hinted_total,
        "version_hinted_external_scripts": version_hinted_total,
        "external_with_query_params": external_with_query_params_total,
        "inline_module_scripts": inline_module_total,
        "inline_json_like_scripts": inline_json_like_total,
        "inline_importmap_scripts": inline_importmap_total,
        "inline_with_close_guard": inline_with_close_guard_total,
        "page_sources_total": page_sources_total,
        "external_scripts_with_page_link": external_with_page_link_total,
        "inline_scripts_with_page_link": inline_with_page_link_total,
        "multi_page_script_links": multi_page_script_links,
        "unique_external_hosts": unique_external_hosts,
        "unique_source_page_hosts": unique_source_page_hosts,
        "internal_page_sources": internal_page_sources,
        "external_page_sources": external_page_sources,
        "pages_with_inline_scripts": pages_with_inline_scripts,
        "pages_with_external_scripts": pages_with_external_scripts,
        "max_external_scripts_on_page": max_external_scripts_on_page,
        "max_inline_scripts_on_page": max_inline_scripts_on_page,
        "avg_external_scripts_per_page": avg_external_scripts_per_page,
        "avg_inline_scripts_per_page": avg_inline_scripts_per_page,
        **endpoint_summary,
        **endpoint_linkage_summary,
    }
    has_inventory = bool(external_scripts or inline_scripts)
    coverage = {
        "external_scripts_linked_ratio": float(external_with_page_link_total / external_total) if external_total > 0 else 0.0,
        "inline_scripts_linked_ratio": float(inline_with_page_link_total / len(inline_scripts)) if len(inline_scripts) > 0 else 0.0,
        "page_sources_complete": bool(page_sources_total > 0) if has_inventory else True,
        "linkage_mode": "single_page_passive",
    }
    return {
        "external_scripts": external_scripts,
        "inline_scripts": inline_scripts,
        "endpoint_candidates": endpoint_candidates,
        "endpoint_linkage": endpoint_linkage,
        "secret_hints": secret_hints,
        "page_sources": page_sources,
        "summary": summary,
        "coverage": coverage,
    }
