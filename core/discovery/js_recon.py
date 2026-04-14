from __future__ import annotations

import hashlib
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse


def empty_js_recon_contract() -> dict[str, Any]:
    return {
        "external_scripts": [],
        "inline_scripts": [],
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
        "page_sources_total": len(page_sources),
        "external_scripts_with_page_link": external_with_page_link_total,
        "inline_scripts_with_page_link": inline_with_page_link_total,
        "multi_page_script_links": multi_page_script_links,
    }
    return {
        "external_scripts": external_scripts,
        "inline_scripts": inline_scripts,
        "page_sources": page_sources,
        "summary": summary,
    }
