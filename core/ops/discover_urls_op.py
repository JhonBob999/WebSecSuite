from __future__ import annotations

import logging
from typing import Any, Dict

import httpx

from core.cookies.storage import load_cookiejar
from core.discovery.candidate_generation import generate_candidates
from core.discovery.url_discovery import discover, parse_forms_from_html
from core.scraper.request_params import normalize_params

logger = logging.getLogger(__name__)


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


def _fetch_html(url: str, params: Dict[str, Any]) -> tuple[str, str, Dict[str, str]]:
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
        return resp.text, str(resp.url), dict(resp.headers)


def _is_html(headers: Dict[str, Any]) -> bool:
    if not headers:
        return True
    ct = headers.get("content-type") or headers.get("Content-Type")
    if not ct:
        return True
    return "html" in str(ct).lower()


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
            return {"error": "No URL provided for discovery", "stats": {}, "urls": {}, "query_params": {}, "parameter_intelligence": []}
        try:
            html, final_url, headers = _fetch_html(base_url, params)
            base_url = final_url or base_url
        except httpx.HTTPError as e:
            return {"error": f"HTTP error: {e}", "stats": {}, "urls": {}, "query_params": {}, "parameter_intelligence": []}
        except Exception as e:  # pragma: no cover - defensive fallback
            return {"error": f"Unhandled fetch error: {e}", "stats": {}, "urls": {}, "query_params": {}, "parameter_intelligence": []}
    else:
        res_ctx = ctx.get("result")
        headers = dict(res_ctx.get("headers") or {}) if isinstance(res_ctx, dict) else {}

    result = discover(html or "", base_url)
    forms_pack = (
        parse_forms_from_html(html, base_url)
        if html and _is_html(headers)
        else {"forms": [], "summary": {"forms_total": 0, "inputs_total": 0, "unique_input_names": 0}}
    )
    result["source"] = {
        "base_url": base_url,
        "content_len": len(html or ""),
        "html_provided": "html" in ctx,
        "content_type": headers.get("content-type") or headers.get("Content-Type") if isinstance(headers, dict) else None,
    }
    result["forms"] = forms_pack.get("forms", [])
    result["forms_summary"] = forms_pack.get("summary", {"forms_total": 0, "inputs_total": 0, "unique_input_names": 0})

    final_url = (
        base_url
        or result.get("final_url")
        or result.get("source", {}).get("base_url")
        or _infer_base_url(ctx)
        or ctx.get("source_url")
        or ""
    )
    classified_urls_by_scope = result.get("classified_urls_by_scope")
    parameter_intelligence = result.get("parameter_intelligence") if "parameter_intelligence" in result else None

    try:
        result["candidates"] = generate_candidates(
            final_url=final_url,
            classified_urls_by_scope=classified_urls_by_scope,
            parameter_intelligence=parameter_intelligence,
        )
    except Exception:
        logger.exception("Discover URLs candidate generation failed; using baseline fallback.")
        try:
            result["candidates"] = generate_candidates(
                final_url=final_url,
                classified_urls_by_scope=None,
                parameter_intelligence=None,
            )
        except Exception:
            logger.exception("Discover URLs baseline candidate generation failed.")
            result["candidates"] = {"summary": {}}

    result["candidates_summary"] = result["candidates"].get("summary", {})
    return result
