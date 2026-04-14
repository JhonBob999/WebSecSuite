from __future__ import annotations

import hashlib
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse


def empty_js_recon_contract() -> dict[str, Any]:
    return {
        "external_scripts": [],
        "inline_scripts": [],
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


class _ScriptSourceHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.external: list[dict[str, Any]] = []
        self.inline_texts: list[str] = []
        self._in_inline_script = False
        self._inline_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if str(tag).lower() != "script":
            return
        script_attrs = _normalize_script_attrs(attrs)
        src_raw = (script_attrs.get("src") or "").strip()
        if src_raw:
            self.external.append({"src": src_raw, "attrs": script_attrs})
            self._in_inline_script = False
            self._inline_chunks = []
            return
        self._in_inline_script = True
        self._inline_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_inline_script and isinstance(data, str):
            self._inline_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if str(tag).lower() != "script":
            return
        if self._in_inline_script:
            self.inline_texts.append("".join(self._inline_chunks))
        self._in_inline_script = False
        self._inline_chunks = []


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

    base_host = (urlparse(base_url or "").hostname or "").lower()
    external_scripts: list[dict[str, Any]] = []
    seen_abs: set[str] = set()
    internal_total = 0
    module_total = 0
    async_total = 0
    defer_total = 0
    integrity_total = 0

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

        if is_internal:
            internal_total += 1
        if flags["module"]:
            module_total += 1
        if flags["async"]:
            async_total += 1
        if flags["defer"]:
            defer_total += 1
        if flags["integrity_present"]:
            integrity_total += 1

        external_scripts.append(
            {
                "src": src,
                "absolute_url": absolute_url,
                "host": host,
                "path": path,
                "query": query,
                "is_internal": is_internal,
                "type_hint": "javascript",
                "attrs": flags,
            }
        )

    inline_scripts: list[dict[str, Any]] = []
    inline_nonempty_total = 0
    for idx, inline_text in enumerate(parser.inline_texts):
        text = inline_text if isinstance(inline_text, str) else ""
        stripped = text.strip()
        if stripped:
            inline_nonempty_total += 1
        inline_scripts.append(
            {
                "index": idx,
                "chars": len(text),
                "sha1": hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest(),
                "preview": _build_preview(text),
            }
        )

    external_total = len(external_scripts)
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
    }
    return {
        "external_scripts": external_scripts,
        "inline_scripts": inline_scripts,
        "summary": summary,
    }
