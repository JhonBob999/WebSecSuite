from __future__ import annotations

from urllib.parse import urlparse

_ASSET_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".gif",
    ".woff",
    ".woff2",
    ".ttf",
    ".ico",
    ".map",
    ".webp",
)

_PAGE_EXTENSIONS = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp")

_API_MARKERS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/")
_AUTH_MARKERS = ("login", "logout", "signin", "signup", "register", "auth", "session")
_ADMIN_MARKERS = ("admin", "dashboard", "manage", "panel", "wp-admin")
_UPLOAD_MARKERS = ("upload", "file-upload", "attachments", "media", "import")


def _extract_path(url_or_path: str | None) -> str:
    value = (url_or_path or "").strip()
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return parsed.path or "/"
    if value.startswith("/"):
        return value
    if "://" in value:
        return parsed.path or ""
    return value


def classify_endpoint_type(url_or_path: str | None) -> str:
    """
    Classify URL/path into a basic endpoint type.
    Returns one of: api, auth, admin, upload, asset, page, unknown.
    """
    path = _extract_path(url_or_path).strip()
    if not path:
        return "unknown"

    low = path.lower()

    if low.endswith(_ASSET_EXTENSIONS):
        return "asset"
    if any(marker in low for marker in _API_MARKERS):
        return "api"
    if any(marker in low for marker in _AUTH_MARKERS):
        return "auth"
    if any(marker in low for marker in _ADMIN_MARKERS):
        return "admin"
    if any(marker in low for marker in _UPLOAD_MARKERS):
        return "upload"

    if low.endswith("/") or low == "/":
        return "page"
    if low.endswith(_PAGE_EXTENSIONS):
        return "page"
    if "." not in low.rsplit("/", 1)[-1]:
        return "page"

    return "unknown"
