from __future__ import annotations


VIEWER_KEYWORD_PACKS = {
    "Recon Basic": (
        "admin",
        "login",
        "dashboard",
        "api",
        "token",
        "debug",
        "config",
        "redirect",
    ),
    "JS / API Review": (
        "fetch",
        "axios",
        "graphql",
        "api/",
        "endpoint",
        "bearer",
        "localStorage",
        "sessionStorage",
        "websocket",
    ),
    "Auth / Admin Review": (
        "login",
        "logout",
        "signin",
        "signup",
        "admin",
        "auth",
        "csrf",
        "jwt",
        "session",
        "cookie",
        "role",
    ),
    "File / Path / Redirect Review": (
        "upload",
        "download",
        "file",
        "path",
        "redirect",
        "returnUrl",
        "next=",
        "callback",
        "backup",
        ".env",
    ),
}


def keyword_pack_names() -> list[str]:
    return list(VIEWER_KEYWORD_PACKS.keys())


def keywords_for_pack(pack_name: str) -> list[str]:
    return list(VIEWER_KEYWORD_PACKS.get(pack_name, ()))
