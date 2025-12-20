from __future__ import annotations

from typing import Any, Dict

import httpx

from core.cookies.storage import load_cookiejar
from core.discovery.url_discovery import discover
from core.scraper.request_params import normalize_params


def _headers_with_ua(params: Dict[str, Any]) -> Dict[str, Any]:
    headers = dict(params.get("headers") or {})
    ua = params.get("user_agent")
    if ua and not any(k.lower() == "user-agent" for k in headers.keys()):
        headers["User-Agent"] = ua
    return headers


def _infer_base_url(task_ctx: dict) -> str:
    return (
        task_ctx.get("final_url")
        or task_ctx.get("url")
        or (task_ctx.get("result") or {}).get("final_url", "")
    )


def _fetch_html(url: str, params: Dict[str, Any]) -> tuple[str, str]:
    cookies, _, _ = load_cookiejar(url=url, cookie_file=params.get("cookie_file"))
    headers = _headers_with_ua(params)
    proxy = params.get("proxy") or None
    timeout = params.get("timeout")

    with httpx.Client(
        timeout=timeout,
        headers=headers,
        proxy=proxy,
        follow_redirects=True,
        cookies=cookies,
    ) as client:
        resp = client.get(url)
        return resp.text, str(resp.url)


def run(task_ctx: dict) -> dict:
    """
    Entry point for synchronous URL discovery:
    - use provided HTML if present;
    - otherwise perform GET via httpx with normalized params and cookies.
    """
    ctx = dict(task_ctx or {})
    html = ctx.get("html")
    params = normalize_params(ctx.get("params") or ctx.get("request") or {})

    base_url = _infer_base_url(ctx)
    if not html:
        if not base_url:
            return {"error": "No URL provided for discovery", "stats": {}, "urls": {}, "query_params": {}}
        try:
            html, final_url = _fetch_html(base_url, params)
            base_url = final_url or base_url
        except httpx.HTTPError as e:
            return {"error": f"HTTP error: {e}", "stats": {}, "urls": {}, "query_params": {}}
        except Exception as e:  # pragma: no cover - defensive fallback
            return {"error": f"Unhandled fetch error: {e}", "stats": {}, "urls": {}, "query_params": {}}

    result = discover(html or "", base_url)
    result["source"] = {
        "base_url": base_url,
        "content_len": len(html or ""),
        "html_provided": "html" in ctx,
    }
    return result
