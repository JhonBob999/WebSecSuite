from core.discovery.url_discovery import (
    discover,
    extract_query_params,
    extract_urls_from_html,
    normalize_url,
    parse_forms_from_html,
    split_internal_external,
)


SAMPLE_HTML = """
<html><body>
<a href="/login?next=/dashboard">login</a>
<a href="https://external.com/page">ext</a>
<script src="/static/app.js"></script>
<form action="/submit" method="post">
    <input name="q" value="x">
    <input type="hidden" name="csrf" value="abc">
</form>
</body></html>
"""


def test_normalize_url_resolves_relative_and_drops_fragment():
    assert normalize_url("/path?a=1#frag", "https://Example.com/base/") == "https://example.com/path?a=1"


def test_normalize_url_resolves_relative_path_against_base_dir():
    assert normalize_url("relative/page", "https://example.com/dir/") == "https://example.com/dir/relative/page"


def test_normalize_url_resolves_protocol_relative():
    assert normalize_url("//cdn.example.com/a.js", "https://example.com") == "https://cdn.example.com/a.js"


def test_normalize_url_rejects_javascript_scheme():
    assert normalize_url("javascript:alert(1)", "https://example.com") is None


def test_normalize_url_rejects_empty_or_none():
    assert normalize_url("", "https://example.com") is None
    assert normalize_url(None, "https://example.com") is None


def test_extract_urls_from_html_collects_href_src_and_form_action():
    urls = extract_urls_from_html(SAMPLE_HTML, "https://example.com/")
    assert urls == [
        "https://example.com/login?next=/dashboard",
        "https://example.com/static/app.js",
        "https://example.com/submit",
        "https://external.com/page",
    ]


def test_extract_urls_from_html_empty_input():
    assert extract_urls_from_html("", "https://example.com/") == []


def test_split_internal_external_by_hostname():
    urls = extract_urls_from_html(SAMPLE_HTML, "https://example.com/")
    internal, external = split_internal_external(urls, "https://example.com/")
    assert internal == [
        "https://example.com/login?next=/dashboard",
        "https://example.com/static/app.js",
        "https://example.com/submit",
    ]
    assert external == ["https://external.com/page"]


def test_extract_query_params():
    params = extract_query_params("https://example.com/login?next=/dashboard&x=1")
    assert params == {"next": ["/dashboard"], "x": ["1"]}


def test_extract_query_params_no_query_returns_empty_dict():
    assert extract_query_params("https://example.com/login") == {}


def test_parse_forms_from_html_extracts_inputs_and_template():
    result = parse_forms_from_html(SAMPLE_HTML, "https://example.com/")
    assert result["summary"] == {
        "forms_total": 1,
        "forms_unique": 1,
        "inputs_total": 2,
        "inputs_unique_total": 2,
        "unique_input_names": 2,
    }
    form = result["forms"][0]
    assert form["method"] == "POST"
    assert form["action"] == "https://example.com/submit"
    assert form["input_names"] == ["q", "csrf"]
    assert form["template"] == {
        "url": "https://example.com/submit",
        "method": "POST",
        "enctype": "application/x-www-form-urlencoded",
        "params": {"q": "x", "csrf": "abc"},
        "files": [],
    }


def test_parse_forms_from_html_empty_input():
    result = parse_forms_from_html("", "https://example.com/")
    assert result == {
        "forms": [],
        "summary": {
            "forms_total": 0,
            "forms_unique": 0,
            "inputs_total": 0,
            "inputs_unique_total": 0,
            "unique_input_names": 0,
        },
    }


def test_discover_orchestrates_urls_and_parameter_intelligence():
    result = discover(SAMPLE_HTML, "https://example.com/")
    assert result["stats"] == {"total": 4, "internal": 3, "external": 1, "with_params": 1}
    assert result["urls"]["internal"] == [
        "https://example.com/login?next=/dashboard",
        "https://example.com/static/app.js",
        "https://example.com/submit",
    ]
    # "next" query param should be picked up by parameter intelligence as an SSRF-flavored url param
    param_names = {p["name"] for p in result["parameter_intelligence"]}
    assert "next" in param_names


def test_discover_empty_html_returns_empty_shape():
    result = discover("", "https://example.com/")
    assert result["stats"] == {"total": 0, "internal": 0, "external": 0, "with_params": 0}
    assert result["urls"]["all"] == []
    assert result["classified_urls_by_scope"] == {"all": [], "internal": [], "external": []}
