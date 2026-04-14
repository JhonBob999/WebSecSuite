from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse


_ENDPOINT_CATEGORY_ORDER: tuple[str, ...] = (
    "api",
    "graphql",
    "auth",
    "login",
    "admin",
    "php",
    "absolute_url",
    "relative_url",
    "route",
    "xhr_hint",
    "unknown",
)

_JS_ROUTE_QUOTED_RE = re.compile(r"(['\"])((?:https?://|/|\.\.?/)[^'\"\n]{1,512})\1")
_JS_ABSOLUTE_RE = re.compile(r"https?://[^\s'\"<>]{3,1024}", re.IGNORECASE)
_JS_RELATIVE_RE = re.compile(r"(?<![\w:])(?:/|\.\.?/)[^\s'\"<>]{1,512}")
_JS_FETCH_CALL_RE = re.compile(r"\bfetch\s*\(\s*(['\"])([^'\"\n]{1,512})\1", re.IGNORECASE)
_JS_AXIOS_CALL_RE = re.compile(r"\baxios(?:\.[a-z]+)?\s*\(\s*(['\"])([^'\"\n]{1,512})\1", re.IGNORECASE)


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


def _classify_endpoint_candidate(value: str, lowered: str) -> str:
    if "graphql" in lowered:
        return "graphql"
    if "/api/" in lowered or lowered.startswith("api/") or "/api?" in lowered:
        return "api"
    if "auth" in lowered:
        return "auth"
    if "login" in lowered:
        return "login"
    if "admin" in lowered:
        return "admin"
    if ".php" in lowered:
        return "php"
    if value.startswith(("http://", "https://")):
        return "absolute_url"
    if value.startswith(("/", "./", "../")):
        return "relative_url"
    return "route"


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
    category = force_category or _classify_endpoint_candidate(value, normalized_value)
    parsed = urlparse(value if value.startswith(("http://", "https://", "/", "./", "../")) else "")
    is_absolute = value.startswith(("http://", "https://"))
    is_relative = value.startswith(("/", "./", "../"))
    host = (parsed.hostname or parsed.netloc or "").lower() if parsed else ""
    path = parsed.path or ""
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
        if not text.strip():
            continue
        source_ref = source_page_url or f"inline_script_{idx}"
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


def empty_js_recon_contract() -> dict[str, Any]:
    return {
        "external_scripts": [],
        "inline_scripts": [],
        "endpoint_candidates": [],
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
        inline_raw_items.append({"index": idx, "text": text})

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
        "page_sources": page_sources,
        "summary": summary,
        "coverage": coverage,
    }
