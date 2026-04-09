from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, List, Tuple

_CONFIDENCE_SCORE = {"low": 1, "medium": 2, "high": 3}


def _normalize_confidence(value: str) -> str:
    v = str(value or "").strip().lower()
    return v if v in _CONFIDENCE_SCORE else "low"


def _max_confidence(a: str, b: str) -> str:
    a_n = _normalize_confidence(a)
    b_n = _normalize_confidence(b)
    return a_n if _CONFIDENCE_SCORE[a_n] >= _CONFIDENCE_SCORE[b_n] else b_n


def _canonical_name(name: str, category: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        return raw
    n = raw.lower()

    # keep versioned library names stable: "React 18.2.0", "Vue 3.4.5"
    if category == "library":
        if n.startswith("jquery"):
            return "jQuery" + raw[len("jQuery"):]
        if n.startswith("react"):
            return "React" + raw[len("React"):]
        if n.startswith("vue"):
            return "Vue" + raw[len("Vue"):]
        if n.startswith("angular"):
            return "Angular" + raw[len("Angular"):]
        if n.startswith("bootstrap"):
            return "Bootstrap" + raw[len("Bootstrap"):]

    canonical_map = {
        "next": "Next.js",
        "nextjs": "Next.js",
        "next.js": "Next.js",
        "wordpress": "WordPress",
        "woocommerce": "WooCommerce",
        "asp.net": "ASP.NET",
        "reactjs": "React",
        "vuejs": "Vue",
        "javascript/jsp": "Java/JSP",
    }
    if n in canonical_map:
        return canonical_map[n]
    return raw


def _evidence_to_list(evidence: Any) -> list[str]:
    if isinstance(evidence, list):
        return sorted({str(x).strip() for x in evidence if str(x).strip()})
    txt = str(evidence or "").strip()
    if not txt:
        return []
    return [txt]


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = re.findall(r"\d+", str(version or ""))
    return tuple(int(p) for p in parts) if parts else ()


def _pick_better_version(current: str, candidate: str) -> str:
    cur = str(current or "").strip()
    cand = str(candidate or "").strip()
    if not cur:
        return cand
    if not cand:
        return cur

    cur_t = _version_tuple(cur)
    cand_t = _version_tuple(cand)
    if cur_t and cand_t:
        if cand_t > cur_t:
            return cand
        if cand_t < cur_t:
            return cur
        return cand if len(cand_t) > len(cur_t) else cur

    # fallback specificity: prefer "x.y.z" over "x.y", then longer token
    cur_dots = cur.count(".")
    cand_dots = cand.count(".")
    if cand_dots > cur_dots:
        return cand
    if cand_dots < cur_dots:
        return cur
    return cand if len(cand) > len(cur) else cur


def _split_library_name_version(name: str) -> tuple[str, str]:
    txt = str(name or "").strip()
    if not txt:
        return "", ""
    m = re.match(r"^(.*?)(?:\s+v?(\d+(?:\.\d+)*))?$", txt)
    if not m:
        return txt, ""
    base = str(m.group(1) or "").strip()
    ver = str(m.group(2) or "").strip()
    return base, ver


def _confidence_from_evidence(evidences: list[str], fallback: str = "low") -> str:
    ev = [str(e or "").strip().lower() for e in (evidences or []) if str(e or "").strip()]
    if not ev:
        return _normalize_confidence(fallback)
    if any(e.startswith("header:") for e in ev):
        return "high"
    if any(e.startswith("cookies:") or e.startswith("html:") for e in ev):
        return "medium"
    return _normalize_confidence(fallback)


def _pick_primary_evidence(evidences: list[str]) -> str:
    ranked: list[tuple[int, str]] = []
    for raw in _evidence_to_list(evidences):
        e = raw.lower()
        if e.startswith("header:"):
            pr = 4
        elif e.startswith("cookies:") or e.startswith("html:"):
            pr = 3
        elif e.startswith("assets:"):
            pr = 2
        else:
            pr = 1
        ranked.append((pr, raw))
    if not ranked:
        return ""
    ranked.sort(key=lambda x: (-x[0], x[1]))
    return ranked[0][1]


def _merge_detections(items: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}

    for it in items or []:
        if not isinstance(it, dict):
            continue
        name = _canonical_name(str(it.get("name") or ""), str(it.get("category") or ""))
        category = str(it.get("category") or "").strip() or "unknown"
        if not name:
            continue

        incoming_version = str(it.get("version") or "").strip()
        if category == "library":
            base_name, parsed_version = _split_library_name_version(name)
            name = base_name or name
            version = _pick_better_version(parsed_version, incoming_version)
            key = (name.lower(), category.lower())
        else:
            version = ""
            key = (name.lower(), category.lower())
        conf = _normalize_confidence(str(it.get("confidence") or "low"))
        ev_list = _evidence_to_list(it.get("evidence"))

        if key not in merged:
            merged[key] = {
                "name": name,
                "category": category,
                "confidence": conf,
                "evidence": ev_list,
                "best_version": version,
            }
            continue

        prev = merged[key]
        prev["confidence"] = _max_confidence(prev.get("confidence", "low"), conf)
        prev["best_version"] = _pick_better_version(str(prev.get("best_version") or ""), version)
        prev_e = _evidence_to_list(prev.get("evidence"))
        prev["evidence"] = sorted(set(prev_e + ev_list))

    out: list[dict] = []
    for _, item in merged.items():
        evidences = _evidence_to_list(item.get("evidence"))
        derived_conf = _confidence_from_evidence(evidences, str(item.get("confidence") or "low"))
        base_name = str(item.get("name") or "")
        best_version = str(item.get("best_version") or "").strip()
        is_library = item.get("category") == "library"
        primary_evidence = _pick_primary_evidence(evidences)
        row = {
            "name": base_name,
            "category": item.get("category", ""),
            "confidence": derived_conf,
            # keep backward-compatible string field; now aggregated
            "evidence": " | ".join(evidences),
            # additive structured evidence for step 1B.x
            "evidence_sources": evidences,
            "primary_evidence": primary_evidence,
        }
        if is_library and best_version:
            row["version"] = best_version
        out.append(row)

    out.sort(
        key=lambda x: (
            -_CONFIDENCE_SCORE.get(_normalize_confidence(str(x.get("confidence") or "low")), 0),
            str(x.get("category") or ""),
            str(x.get("name") or ""),
        )
    )
    return out



def _collapse_framework_libraries(items: list[dict]) -> list[dict]:
    """
    Step 1B.1 follow-up:
    collapse library-style React/Vue/Angular entries into the main framework entry.
    Keeps payload compatible and reduces duplicate framework rows.
    """
    if not items:
        return []

    framework_roots = {
        "react": ("React", "frontend_framework"),
        "vue": ("Vue", "frontend_framework"),
        "angular": ("Angular", "frontend_framework"),
    }

    by_key: dict[tuple[str, str], dict] = {}
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or "").strip()
        category = str(it.get("category") or "").strip() or "unknown"
        conf = _normalize_confidence(str(it.get("confidence") or "low"))
        ev_list = _evidence_to_list(it.get("evidence_sources") or it.get("evidence"))
        version = str(it.get("version") or "").strip() if category == "library" else ""

        root_key = None
        lname = name.lower()
        if category == "library":
            for root in framework_roots.keys():
                if lname == root or lname.startswith(root + " "):
                    root_key = root
                    break

        if root_key is not None:
            canonical_name, canonical_cat = framework_roots[root_key]
            key = (canonical_name.lower(), canonical_cat.lower())
        else:
            key = (name.lower(), category.lower())

        if key not in by_key:
            by_key[key] = {
                "name": framework_roots[root_key][0] if root_key is not None else name,
                "category": framework_roots[root_key][1] if root_key is not None else category,
                "confidence": conf,
                "evidence_sources": ev_list,
                "best_version": "" if root_key is not None else version,
            }
            continue

        prev = by_key[key]
        prev["confidence"] = _max_confidence(prev.get("confidence", "low"), conf)
        prev_e = _evidence_to_list(prev.get("evidence_sources"))
        prev["evidence_sources"] = sorted(set(prev_e + ev_list))
        if prev.get("category") == "library":
            prev["best_version"] = _pick_better_version(str(prev.get("best_version") or ""), version)

    out: list[dict] = []
    for it in by_key.values():
        evidences = _evidence_to_list(it.get("evidence_sources"))
        row = {
            "name": it.get("name", ""),
            "category": it.get("category", ""),
            "confidence": _normalize_confidence(str(it.get("confidence") or "low")),
            "evidence": " | ".join(evidences),
            "evidence_sources": evidences,
            "primary_evidence": _pick_primary_evidence(evidences),
        }
        if row.get("category") == "library":
            best_version = str(it.get("best_version") or "").strip()
            if best_version:
                row["version"] = best_version
        out.append(row)

    out.sort(
        key=lambda x: (
            -_CONFIDENCE_SCORE.get(_normalize_confidence(str(x.get("confidence") or "low")), 0),
            str(x.get("category") or ""),
            str(x.get("name") or ""),
        )
    )
    return out

def _build_top_stack(technologies: list[dict], limit: int = 5) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for t in technologies or []:
        name = _canonical_name(str(t.get("name") or ""), str(t.get("category") or ""))
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
        if len(out) >= max(1, int(limit)):
            break
    return out

class _AssetParser(HTMLParser):
    """Safe stdlib-only parser for <script src> and <link href>."""

    def __init__(self) -> None:
        super().__init__()
        self.script_src: list[str] = []
        self.link_href: list[str] = []
        self.meta_generator: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[Tuple[str, str | None]]) -> None:
        low = tag.lower()
        attrs_dict = {str(k).lower(): (v or "") for k, v in attrs if k}
        if low == "script":
            src = (attrs_dict.get("src") or "").strip()
            if src:
                self.script_src.append(src)
        elif low == "link":
            href = (attrs_dict.get("href") or "").strip()
            if href:
                self.link_href.append(href)
        elif low == "meta" and (attrs_dict.get("name") or "").lower() == "generator":
            content = (attrs_dict.get("content") or "").strip()
            if content:
                self.meta_generator.append(content)


def _safe_lower_map(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        key = str(k or "").strip().lower()
        if not key:
            continue
        out[key] = str(v or "").strip()
    return out


def _safe_cookie_names(cookie_names: Iterable[str] | None) -> list[str]:
    names: set[str] = set()
    for raw in (cookie_names or []):
        candidate = str(raw or "").strip()
        if not candidate:
            continue
        names.add(candidate)
    return sorted(names)


def _cookie_names_from_set_cookie_headers(set_cookie_headers: list[str] | None) -> list[str]:
    names: set[str] = set()
    for line in (set_cookie_headers or []):
        if not line:
            continue
        first = str(line).split(";", 1)[0]
        if "=" not in first:
            continue
        name = first.split("=", 1)[0].strip()
        if name:
            names.add(name)
    return sorted(names)


def _parse_assets(html: str) -> tuple[list[str], list[str], list[str]]:
    if not html:
        return [], [], []
    parser = _AssetParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        return [], [], []
    return sorted(set(parser.script_src)), sorted(set(parser.link_href)), sorted(set(parser.meta_generator))


def _detect_version_from_url(url: str) -> str:
    # common patterns: react@18.2.0, vue-3.4.5, jquery/3.7.1, angular.min.js?ver=1.8.3
    patterns = [
        r"[@/_-]v?(\d+\.\d+(?:\.\d+)?)",
        r"[?&](?:ver|version|v)=(\d+\.\d+(?:\.\d+)?)",
    ]
    for p in patterns:
        m = re.search(p, url, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _push_detection(bucket: list[dict], name: str, category: str, confidence: str, evidence: str) -> None:
    if not evidence:
        return
    bucket.append(
        {
            "name": name,
            "category": category,
            "confidence": confidence,
            "evidence": evidence,
        }
    )


def build_passive_fingerprint(
    *,
    headers: dict[str, Any] | None,
    html: str,
    cookie_names: list[str] | None,
    set_cookie_headers: list[str] | None,
) -> dict:
    """
    Passive, signal-based technology fingerprinting from already collected data.
    Never raises; returns stable structure for downstream scoring/CVE mapping.
    """
    headers_l = _safe_lower_map(headers or {})

    cookies_seen = set(_safe_cookie_names(cookie_names))
    cookies_seen.update(_cookie_names_from_set_cookie_headers(set_cookie_headers))
    cookies_seen_list = sorted(cookies_seen)

    script_src, link_href, meta_generator = _parse_assets(html or "")
    html_l = (html or "").lower()

    technologies: list[dict] = []
    infra: list[dict] = []

    # --- server/framework headers ---
    header_signals = {
        "server": "Server",
        "x-powered-by": "X-Powered-By",
        "x-aspnet-version": "X-AspNet-Version",
        "x-generator": "X-Generator",
        "via": "Via",
    }
    for hk, human in header_signals.items():
        hv = headers_l.get(hk, "")
        if hv:

            name = human if hk != "x-powered-by" else hv
            
            if hk == "server":
                name = hv
            elif hk == "via":
                name = f"Via ({hv})"
            else:
                name = hv if hk == "x-powered-by" else human
            cat = "server" if hk in {"server", "via"} else "framework"
            _push_detection(
                technologies,
                name=name,
                category=cat,
                confidence="high" if hk in {"x-powered-by", "x-aspnet-version", "x-generator"} else "medium",
                evidence=f"header:{human}={hv}",
            )

    # --- CDN / WAF hints ---
    header_blob = "\n".join(f"{k}: {v}" for k, v in headers_l.items())
    waf_markers = [
        ("Cloudflare", ["cf-ray", "cf-cache-status", "__cf_bm", "cf_clearance", "server: cloudflare"]),
        ("Akamai", ["akamai", "x-akamai", "akamaighost"]),
        ("Fastly", ["x-served-by", "x-cache", "fastly"]),
        ("Imperva", ["incap_ses", "visid_incap", "x-iinfo"]),
    ]
    for name, markers in waf_markers:
        matched = [m for m in markers if m in header_blob.lower() or m in " ".join(cookies_seen_list).lower()]
        if matched:
            _push_detection(
                infra,
                name=name,
                category="cdn_waf",
                confidence="medium" if len(matched) == 1 else "high",
                evidence=f"signals:{', '.join(sorted(set(matched)))}",
            )

    # --- cookie tech hints ---
    cookie_map = [
        ("PHP", "session", ["PHPSESSID"]),
        ("Java/JSP", "session", ["JSESSIONID"]),
        ("ASP.NET", "session", ["ASP.NET_SessionId"]),
        ("Laravel", "framework", ["laravel_session"]),
        ("WordPress", "cms", ["wordpress_", "wp-settings-"]),
        ("WooCommerce", "cms", ["woocommerce_", "wp_woocommerce_session_"]),
        ("Express", "framework", ["connect.sid"]),
        ("Cloudflare", "cdn_waf", ["__cf_bm", "cf_clearance"]),
    ]

    cookies_blob = "\n".join(cookies_seen_list).lower()
    for tech_name, cat, markers in cookie_map:
        matched = [m for m in markers if m.lower() in cookies_blob]
        if matched:
            target = infra if cat == "cdn_waf" else technologies
            _push_detection(
                target,
                name=tech_name,
                category=cat,
                confidence="medium",
                evidence=f"cookies:{', '.join(matched)}",
            )

    # --- HTML/framework markers ---
    html_markers = [
        ("WordPress", "cms", ["wp-content", "wp-includes", "wordpress"]),
        ("Drupal", "cms", ["drupal-settings-json", "sites/all/", "drupal"]),
        ("Joomla", "cms", ["/media/system/js/", "joomla"]),
        ("React", "frontend_framework", ["react", "__react"], ["react", "react-dom"]),
        ("Vue", "frontend_framework", ["vue"], ["vue"]),
        ("Next.js", "frontend_framework", ["__next", "_next/static"], ["next"]),
        ("Angular", "frontend_framework", ["ng-app", "ng-version", "angular"], ["angular"]),
    ]

    assets_blob = "\n".join(script_src + link_href).lower()
    for item in html_markers:
        if len(item) == 3:
            name, cat, markers = item
            asset_markers = []
        else:
            name, cat, markers, asset_markers = item
        matched_html = [m for m in markers if m in html_l]
        matched_assets = [m for m in asset_markers if m in assets_blob]
        if matched_html or matched_assets:
            conf = "high" if (matched_html and matched_assets) else "medium"
            parts = []
            if matched_html:
                parts.append(f"html:{', '.join(sorted(set(matched_html)))}")
            if matched_assets:
                parts.append(f"assets:{', '.join(sorted(set(matched_assets)))}")
            _push_detection(technologies, name=name, category=cat, confidence=conf, evidence="; ".join(parts))

    # --- version hints from assets ---
    lib_markers = {
        "jQuery": ["jquery"],
        "Bootstrap": ["bootstrap"],
        "React": ["react", "react-dom"],
        "Vue": ["vue"],
        "Angular": ["angular"],
    }
    for asset_url in script_src + link_href:
        low = asset_url.lower()
        for lib_name, markers in lib_markers.items():
            if any(m in low for m in markers):
                ver = _detect_version_from_url(asset_url)
                display = f"{lib_name} {ver}".strip()
                ev = f"asset:{asset_url}"
                _push_detection(
                    technologies,
                    name=display,
                    category="library",
                    confidence="medium" if ver else "low",
                    evidence=ev,
                )


    # de-duplicate by (name, category, evidence)
    def _uniq(items: list[dict]) -> list[dict]:
        seen = set()
        out = []
        for it in items:
            key = (it.get("name"), it.get("category"), it.get("evidence"))
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
        return out

    technologies = _uniq(technologies)
    infra = _uniq(infra)

    # normalize + dedupe + merge repeated detections
    technologies = _merge_detections(technologies)
    technologies = _collapse_framework_libraries(technologies)

    infra = _merge_detections(infra)

    top_stack = _build_top_stack(technologies, limit=5)
    has_cdn = any((i.get("category") == "cdn_waf") for i in infra)
    has_waf_hint = has_cdn

    headers_seen = {
        "server": headers_l.get("server", ""),
        "x_powered_by": headers_l.get("x-powered-by", ""),
        "x_aspnet_version": headers_l.get("x-aspnet-version", ""),
        "x_generator": headers_l.get("x-generator", ""),
        "via": headers_l.get("via", ""),
    }

    if meta_generator and not headers_seen.get("x_generator"):
        headers_seen["x_generator"] = meta_generator[0]

    return {
        "technologies": technologies,
        "infra": infra,
        "headers_seen": headers_seen,
        "cookies_seen": cookies_seen_list,
        "summary": {
            "top_stack": top_stack,
            "has_cdn": bool(has_cdn),
            "has_waf_hint": bool(has_waf_hint),
        },
    }
