from __future__ import annotations

from html.parser import HTMLParser
from typing import Iterable, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

from core.discovery.endpoint_classifier import classify_endpoint_type
from core.discovery.parameter_intelligence import analyze_query_params

try:  # Optional HTML parser if available in the environment
    from bs4 import BeautifulSoup  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    BeautifulSoup = None

MAX_FORM_INPUTS = 200


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


def _normalize_attrs(attrs: dict | list[Tuple[str, str | None]]) -> dict[str, str]:
    if isinstance(attrs, dict):
        items = attrs.items()
    else:
        items = attrs
    normalized: dict[str, str] = {}
    for key, val in items:
        if key is None:
            continue
        name = key.lower()
        if isinstance(val, list):
            normalized[name] = " ".join(str(v) for v in val)
        elif val is None:
            normalized[name] = ""
        else:
            normalized[name] = str(val)
    return normalized


def _normalize_form_action(action: str | None, base_url: str) -> str:
    candidate = (action or "").strip()
    if not candidate or candidate == "#":
        return base_url
    normalized = normalize_url(candidate, base_url)
    if normalized:
        return normalized
    try:
        return urljoin(base_url or "", candidate)
    except Exception:
        return candidate


def _new_form(attrs: dict[str, str], base_url: str) -> dict:
    method = (attrs.get("method") or "GET").strip().upper() or "GET"
    enctype = (attrs.get("enctype") or "application/x-www-form-urlencoded").strip() or "application/x-www-form-urlencoded"
    enctype = enctype.lower()
    form = {
        "method": method,
        "action": _normalize_form_action(attrs.get("action"), base_url),
        "enctype": enctype,
        "id": attrs.get("id") or "",
        "name": attrs.get("name") or "",
        "inputs": [],
        "has_file": "multipart/form-data" in enctype.lower(),
        "input_names": [],
        "inputs_total_raw": 0,
        "truncated": False,
    }
    return form


def _register_input(form: dict, field: dict, max_inputs: int = MAX_FORM_INPUTS) -> None:
    form["inputs_total_raw"] = form.get("inputs_total_raw", 0) + 1
    if field.get("type") == "file":
        form["has_file"] = True
    if len(form["inputs"]) < max_inputs:
        form["inputs"].append(field)
    else:
        form["truncated"] = True
    if form.get("inputs_total_raw", 0) > max_inputs:
        form["truncated"] = True
    name = field.get("name") or ""
    if name and name not in form["input_names"]:
        form["input_names"].append(name)


def _build_field(
    tag: str,
    attrs: dict[str, str],
    text: str = "",
    options: list[dict] | None = None,
    selected_value: str | list[str] = "",
    multiple: bool = False,
) -> dict:
    tag = tag.lower()
    required = "required" in attrs
    checked = "checked" in attrs
    placeholder = attrs.get("placeholder") or ""
    name = attrs.get("name") or ""

    if tag == "textarea":
        field_type = "textarea"
        value = text or ""
        options = []
        checked = False
    elif tag == "select":
        field_type = "select"
        options = options or []
        checked = False
        value = selected_value or ""
        if isinstance(selected_value, list):
            value = selected_value
        elif not selected_value and options:
            first = options[0]
            value = first.get("value") or first.get("label") or ""
    elif tag == "button":
        field_type = (attrs.get("type") or "submit").lower() or "submit"
        value = attrs.get("value") or text or ""
        options = []
    else:
        field_type = (attrs.get("type") or "text").lower() or "text"
        value = attrs.get("value") or ""
        options = []

    return {
        "tag": tag,
        "type": field_type,
        "name": name,
        "value": value,
        "required": bool(required),
        "placeholder": placeholder,
        "checked": bool(checked),
        "options": options,
        "multiple": bool(multiple),
    }


def _parse_forms_with_bs4(html: str, base_url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    forms: list[dict] = []
    for form_tag in soup.find_all("form"):
        form_attrs = _normalize_attrs(form_tag.attrs)
        form = _new_form(form_attrs, base_url)
        for field_tag in form_tag.find_all(["input", "select", "textarea", "button"]):
            attrs = _normalize_attrs(field_tag.attrs)
            if field_tag.name == "select":
                options: list[dict] = []
                selected_values: list[str] = []
                is_multiple = "multiple" in attrs
                for option_tag in field_tag.find_all("option"):
                    option_attrs = _normalize_attrs(option_tag.attrs)
                    option_label = option_tag.get_text() or ""
                    option_value = option_attrs.get("value") or ""
                    options.append({"value": option_value, "label": option_label})
                    if "selected" in option_attrs:
                        selected_values.append(option_value or option_label)
                if not is_multiple:
                    selected_value = selected_values[0] if selected_values else ""
                else:
                    selected_value = selected_values
                field = _build_field(
                    "select",
                    attrs,
                    options=options,
                    selected_value=selected_value,
                    multiple=is_multiple,
                )
            elif field_tag.name == "textarea":
                field = _build_field("textarea", attrs, text=field_tag.get_text() or "")
            elif field_tag.name == "button":
                field = _build_field("button", attrs, text=(field_tag.get_text() or "").strip())
            else:
                field = _build_field("input", attrs)
            _register_input(form, field)
        forms.append(form)
    return forms


class _SafeHTMLFormParser(HTMLParser):
    """Fallback form parser when BeautifulSoup is unavailable."""

    def __init__(self, base_url: str, max_inputs: int = MAX_FORM_INPUTS) -> None:
        super().__init__()
        self.base_url = base_url
        self.max_inputs = max_inputs
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self._current_textarea: dict | None = None
        self._current_select: dict | None = None
        self._current_option: dict | None = None
        self._current_option_text: list[str] = []
        self._current_button: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[Tuple[str, str | None]]) -> None:
        attrs_dict = _normalize_attrs(attrs)
        if tag == "form":
            if self._current_form:
                self.forms.append(self._current_form)
            self._current_textarea = None
            self._current_select = None
            self._current_option = None
            self._current_option_text = []
            self._current_button = None
            self._current_form = _new_form(attrs_dict, self.base_url)
            return

        if not self._current_form:
            return

        if tag == "input":
            _register_input(self._current_form, _build_field("input", attrs_dict), self.max_inputs)
        elif tag == "button":
            self._current_button = {"attrs": attrs_dict, "text": ""}
        elif tag == "textarea":
            self._current_textarea = {"attrs": attrs_dict, "text": ""}
        elif tag == "select":
            self._current_select = {
                "attrs": attrs_dict,
                "options": [],
                "selected": [],
                "multiple": "multiple" in attrs_dict,
            }
        elif tag == "option" and self._current_select is not None:
            self._current_option = {"attrs": attrs_dict}
            self._current_option_text = []

    def handle_data(self, data: str) -> None:
        if self._current_textarea is not None:
            self._current_textarea["text"] += data
        if self._current_option_text is not None and self._current_option is not None:
            self._current_option_text.append(data)
        if self._current_button is not None:
            self._current_button["text"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            if self._current_form:
                self.forms.append(self._current_form)
                self._current_form = None
            self._current_textarea = None
            self._current_select = None
            self._current_option = None
            self._current_option_text = []
            self._current_button = None
            return

        if not self._current_form:
            return

        if tag == "textarea" and self._current_textarea is not None:
            field = _build_field("textarea", self._current_textarea["attrs"], text=self._current_textarea["text"])
            _register_input(self._current_form, field, self.max_inputs)
            self._current_textarea = None
            return

        if tag == "option" and self._current_select is not None and self._current_option is not None:
            option_attrs = self._current_option["attrs"]
            option_text = "".join(self._current_option_text).strip()
            option_value = option_attrs.get("value") or ""
            self._current_select["options"].append({"value": option_value, "label": option_text})
            if "selected" in option_attrs:
                self._current_select["selected"].append(option_value or option_text)
            self._current_option = None
            self._current_option_text = []
            return

        if tag == "button" and self._current_button is not None:
            field = _build_field("button", self._current_button["attrs"], text=self._current_button.get("text", ""))
            _register_input(self._current_form, field, self.max_inputs)
            self._current_button = None
            return

        if tag == "select" and self._current_select is not None:
            selected_raw = self._current_select.get("selected") or []
            selected_value: str | list[str]
            if self._current_select.get("multiple"):
                selected_value = selected_raw
            else:
                selected_value = selected_raw[0] if selected_raw else ""
            field = _build_field(
                "select",
                self._current_select["attrs"],
                options=self._current_select["options"],
                selected_value=selected_value,
                multiple=self._current_select.get("multiple", False),
            )
            _register_input(self._current_form, field, self.max_inputs)
            self._current_select = None

    def close(self) -> None:
        super().close()
        if self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None
        self._current_textarea = None
        self._current_select = None
        self._current_option = None
        self._current_option_text = []
        self._current_button = None


def parse_forms_from_html(html: str, base_url: str) -> dict:
    """
    Parse forms and inputs from HTML, including summary counters.
    """
    base_url = base_url or ""
    if not html:
        return {
            "forms": [],
            "summary": {
                "forms_total": 0,
                "forms_unique": 0,
                "inputs_total": 0,
                "inputs_unique_total": 0,
                "unique_input_names": 0,
            },
        }

    forms: list[dict] = []
    if BeautifulSoup is not None:
        try:
            forms = _parse_forms_with_bs4(html, base_url)
        except Exception:
            forms = []

    if not forms:
        parser = _SafeHTMLFormParser(base_url=base_url, max_inputs=MAX_FORM_INPUTS)
        try:
            parser.feed(html)
            parser.close()
            forms = parser.forms
        except Exception:
            forms = []

    forms_total = len(forms)
    inputs_total_raw = sum(f.get("inputs_total_raw", len(f.get("inputs", []))) for f in forms)

    unique_forms: list[dict] = []
    seen_signatures: set[tuple] = set()

    def _form_signature(form: dict) -> tuple:
        method = (form.get("method") or "").upper()
        action = _normalize_form_action(form.get("action"), base_url)
        enctype = (form.get("enctype") or "").lower()
        names = sorted({inp.get("name") or "" for inp in form.get("inputs", []) if inp.get("name")})
        return (method, action, enctype, tuple(names))

    for form in forms:
        sig = _form_signature(form)
        if sig in seen_signatures:
            continue
        seen_signatures.add(sig)
        unique_forms.append(form)

    def _build_template(form: dict) -> dict:
        method = (form.get("method") or "GET").upper()
        action = _normalize_form_action(form.get("action"), base_url)
        enctype = (form.get("enctype") or "").lower()
        params: dict[str, object] = {}
        files: list[str] = []

        for field in form.get("inputs", []):
            name = field.get("name") or ""
            if field.get("type") == "file" and name:
                files.append(name)
            if not name:
                continue

            tag = (field.get("tag") or "").lower()
            ftype = (field.get("type") or "").lower()
            checked = bool(field.get("checked"))
            value = field.get("value")
            options = field.get("options") or []
            multiple = bool(field.get("multiple"))

            if tag == "select":
                if multiple:
                    selected_list = value if isinstance(value, list) else []
                    params[name] = list(selected_list)
                else:
                    selected_val = value if isinstance(value, str) else ""
                    if not selected_val and options:
                        first = options[0]
                        selected_val = first.get("value") or first.get("label") or ""
                    params[name] = selected_val
                continue

            if tag == "textarea":
                params[name] = value or ""
                continue

            if ftype in {"checkbox", "radio"}:
                if checked:
                    params[name] = value or "on"
                else:
                    params[name] = ""
                continue

            params[name] = value or ""

        return {
            "url": action,
            "method": method,
            "enctype": enctype,
            "params": params,
            "files": files,
        }

    for form in unique_forms:
        form["template"] = _build_template(form)

    summary = {
        "forms_total": forms_total,
        "forms_unique": len(unique_forms),
        "inputs_total": inputs_total_raw,
        "inputs_unique_total": sum(f.get("inputs_total_raw", len(f.get("inputs", []))) for f in unique_forms),
        "unique_input_names": len({name for f in unique_forms for name in f.get("input_names", []) if name}),
    }
    return {"forms": unique_forms, "summary": summary}


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

    param_names = sorted({name for param_dict in params_map.values() for name in param_dict.keys()})
    parameter_intelligence_pack = analyze_query_params(param_names)
    parameter_intelligence = parameter_intelligence_pack.get("params", [])
    parameter_intelligence_summary = parameter_intelligence_pack.get(
        "summary",
        {"total": 0, "by_category": {}, "high_risk": 0},
    )
    classified_urls = build_scored_classified_urls(urls, params_map, parameter_intelligence)
    classified_internal_urls = build_scored_classified_urls(internal, params_map, parameter_intelligence)
    classified_external_urls = build_scored_classified_urls(external, params_map, parameter_intelligence)

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
            "classified": classified_urls,
        },
        "classified_urls": classified_urls,
        "classified_urls_by_scope": {
            "all": classified_urls,
            "internal": classified_internal_urls,
            "external": classified_external_urls,
        },
        "query_params": params_map,
        "parameter_intelligence": parameter_intelligence,
        "parameter_intelligence_summary": parameter_intelligence_summary,
        "stats": stats,
    }


def _score_endpoint(
    url: str,
    endpoint_type: str,
    query_params: dict[str, dict[str, str]] | None,
    parameter_intelligence: list[dict] | None,
) -> int:
    score = 0
    endpoint_boost = {
        "admin": 5,
        "upload": 5,
        "api": 4,
        "auth": 3,
    }
    score += endpoint_boost.get(endpoint_type, 0)

    lowered_url = (url or "").lower()
    if "?" in lowered_url:
        score += 3

    risky_markers = ("id", "user", "account", "file", "path", "redirect", "url")
    if any(marker in lowered_url for marker in risky_markers):
        score += 2

    if endpoint_type == "asset":
        score -= 5

    params_by_url = query_params or {}
    intel_rows = parameter_intelligence or []
    normalized_param_intel = {
        str(item.get("name") or "").strip().lower()
        for item in intel_rows
        if isinstance(item, dict) and str(item.get("name") or "").strip()
    }
    url_params = params_by_url.get(url) if isinstance(params_by_url, dict) else None
    if isinstance(url_params, dict):
        url_param_names = {str(name).strip().lower() for name in url_params.keys() if str(name).strip()}
        if url_param_names and url_param_names.intersection(normalized_param_intel):
            score += 2

    return score


def _priority_from_score(score: int) -> str:
    if score >= 8:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def build_scored_classified_urls(
    url_list: Iterable[str],
    query_params: dict[str, dict[str, str]] | None = None,
    parameter_intelligence: list[dict] | None = None,
) -> list[dict[str, str | int]]:
    output: list[dict[str, str | int]] = []
    for url in url_list:
        endpoint_type = classify_endpoint_type(url)
        score = _score_endpoint(url, endpoint_type, query_params, parameter_intelligence)
        output.append(
            {
                "url": url,
                "endpoint_type": endpoint_type,
                "score": score,
                "priority": _priority_from_score(score),
            }
        )
    return output
