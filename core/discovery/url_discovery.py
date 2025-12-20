from __future__ import annotations

from html.parser import HTMLParser
from typing import Iterable, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

try:  # Optional HTML parser if available in the environment
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    BeautifulSoup = None


def normalize_url(raw: str | None, base_url: str | None) -> str | None:
    """
    Resolve a raw link against base_url and drop fragments.
    Filters out non-http(s) schemes and returns a normalized absolute URL.
    """
    if not raw:
        return None

    candidate = raw.strip()
    if not candidate or candidate.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None

    absolute = urljoin(base_url or "", candidate)
    parsed = urlparse(absolute)
    if not parsed.scheme or not parsed.netloc:
        return None

    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        fragment="",
        path=parsed.path or "/",
    )
    return urlunparse(normalized)


def _extract_with_bs4(html: str) -> Iterable[str]:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(href=True):
        yield tag["href"]
    for tag in soup.find_all(src=True):
        yield tag["src"]
    for tag in soup.find_all("form"):
        action = tag.get("action")
        if action:
            yield action


class _SafeHTMLLinkParser(HTMLParser):
    """Lightweight fallback extractor when BeautifulSoup is unavailable."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[Tuple[str, str | None]]) -> None:
        for name, val in attrs:
            if name in {"href", "src", "action"} and val:
                self.links.append(val)


def extract_urls_from_html(html: str, base_url: str | None) -> list[str]:
    """
    Parse HTML and collect normalized URLs from href/src/action attributes.
    """
    if not html:
        return []

    raw_links: Iterable[str] = []
    if BeautifulSoup is not None:
        try:
            raw_links = _extract_with_bs4(html)
        except Exception:
            raw_links = []
    if not raw_links:
        parser = _SafeHTMLLinkParser()
        try:
            parser.feed(html)
            raw_links = parser.links
        except Exception:
            raw_links = []

    normalized = {
        url
        for url in (normalize_url(link, base_url) for link in raw_links)
        if url
    }
    return sorted(normalized)


def split_internal_external(urls: Iterable[str], base_url: str | None) -> Tuple[list[str], list[str]]:
    """
    Split URLs into internal/external buckets based on hostname match with base_url.
    """
    parsed_base = urlparse(base_url or "")
    base_host = (parsed_base.hostname or parsed_base.netloc or "").lower()

    internal, external = set(), set()
    for url in urls:
        host = (urlparse(url).hostname or urlparse(url).netloc or "").lower()
        if base_host and host == base_host:
            internal.add(url)
        else:
            external.add(url)

    return sorted(internal), sorted(external)


def extract_query_params(url: str) -> dict:
    parsed = urlparse(url)
    if not parsed.query:
        return {}
    return {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}


def discover(html: str, base_url: str | None) -> dict:
    """
    High-level discovery orchestration.
    Returns a dict with URLs, query params and counters.
    """
    base_url = base_url or ""
    urls = extract_urls_from_html(html or "", base_url)
    internal, external = split_internal_external(urls, base_url)
    params_map = {u: extract_query_params(u) for u in urls}
    params_map = {u: p for u, p in params_map.items() if p}

    stats = {
        "total": len(urls),
        "internal": len(internal),
        "external": len(external),
        "with_params": len(params_map),
    }

    return {
        "base_url": base_url,
        "urls": {
            "all": urls,
            "internal": internal,
            "external": external,
        },
        "query_params": params_map,
        "stats": stats,
    }

