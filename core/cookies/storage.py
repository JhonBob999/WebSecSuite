# core/cookies/storage.py
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List
from http.cookiejar import CookieJar, Cookie
from urllib.parse import urlparse

# ========== FS utils ==========
def cookies_dir() -> Path:
    d = Path("data") / "cookies"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _sanitize_domain(domain: str) -> str:
    # простая нормализация; при желании можно добавить punycode/PSL
    return (domain or "unknown").strip().lower().replace(":", "_")

def file_for_domain(domain: str) -> Path:
    return cookies_dir() / f"cookies_{_sanitize_domain(domain)}.json"

# ========== JSON <-> CookieJar ==========
def _cookie_to_dict(c: Cookie) -> Dict[str, Any]:
    # Набор полей, достаточный для восстановления и совместимый с http.cookiejar
    return {
        "version": c.version,
        "name": c.name,
        "value": c.value,
        "port": c.port,
        "port_specified": c.port_specified,
        "domain": c.domain,
        "domain_specified": c.domain_specified,
        "domain_initial_dot": c.domain_initial_dot,
        "path": c.path,
        "path_specified": c.path_specified,
        "secure": c.secure,
        "expires": c.expires,
        "discard": c.discard,
        "comment": c.comment,
        "comment_url": c.comment_url,
        "rest": c._rest if hasattr(c, "_rest") else {},   # SameSite и пр.
        "rfc2109": c.rfc2109,
    }

def _dict_to_cookie(d: Dict[str, Any]) -> Cookie:
    # Cookie — это namedtuple-подобный объект с большим числом аргументов
    return Cookie(
        version=d.get("version", 0),
        name=d["name"],
        value=d.get("value", ""),
        port=d.get("port"),
        port_specified=d.get("port_specified", False),
        domain=d.get("domain", ""),
        domain_specified=d.get("domain_specified", bool(d.get("domain"))),
        domain_initial_dot=d.get("domain_initial_dot", d.get("domain", "").startswith(".")),
        path=d.get("path", "/"),
        path_specified=d.get("path_specified", True),
        secure=d.get("secure", False),
        expires=d.get("expires"),
        discard=d.get("discard", False),
        comment=d.get("comment"),
        comment_url=d.get("comment_url"),
        rest=d.get("rest", {}),
        rfc2109=d.get("rfc2109", False),
    )
    
def _as_cookiejar(obj) -> CookieJar:
    """
    Привести любые cookies к CookieJar:
    - httpx.Cookies -> .jar (CookieJar)
    - уже CookieJar -> как есть
    - dict / list[tuple] — при желании можно добавить поддержку позже
    """
    if isinstance(obj, CookieJar):
        return obj
    # httpx.Cookies имеет свойство .jar (CookieJar)
    jar_attr = getattr(obj, "jar", None)
    if isinstance(jar_attr, CookieJar):
        return jar_attr
    # fallback: пустой jar (чтобы не падать)
    return CookieJar()

def jar_to_json(jar_like) -> Dict[str, Any]:
    jar = _as_cookiejar(jar_like)
    items: List[Dict[str, Any]] = []
    for c in jar:  # здесь уже точно Cookie
        items.append(_cookie_to_dict(c))
    return {"version": 1, "cookies": items}

def json_to_jar(data: Dict[str, Any]) -> CookieJar:
    from http.cookiejar import CookieJar
    jar = CookieJar()
    for item in data.get("cookies", []):
        jar.set_cookie(_dict_to_cookie(item))
    return jar

# ========== IO (атомарная запись) ==========
def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".cookies_", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)  # атомарно
    finally:
        # если что-то пошло не так — подстрахуемся
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

# ========== Публичное API ==========
def derive_domain_from_url(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        return host.lower()
    except Exception:
        return "unknown"

def load_cookiejar(url: Optional[str] = None, cookie_file: Optional[str] = None) -> Tuple[CookieJar, Path, int]:
    """
    Возвращает (jar, path, loaded_count)
    - если cookie_file задан и существует — грузим его
    - иначе, если задан url — строим путь по домену
    - если файла нет — возвращаем пустой jar и путь назначения
    """
    from http.cookiejar import CookieJar
    jar = CookieJar()

    if cookie_file:
        path = Path(cookie_file)
    else:
        domain = derive_domain_from_url(url or "")
        path = file_for_domain(domain)

    loaded = 0
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            jar = json_to_jar(data)
            loaded = len(list(jar))
        except Exception:
            # поврежденный файл — игнорируем, начинаем с пустого
            jar = CookieJar()
            loaded = 0

    return jar, path, loaded

def save_cookiejar(path: Path, jar_like) -> int:
    jar = _as_cookiejar(jar_like)
    data = jar_to_json(jar)
    _atomic_write_json(path, data)
    return len(data.get("cookies", []))
