from core.discovery.endpoint_classifier import classify_endpoint_type


def test_classifies_asset_by_extension():
    assert classify_endpoint_type("/static/app.js") == "asset"
    assert classify_endpoint_type("https://example.com/img/logo.png") == "asset"


def test_classifies_api_marker():
    assert classify_endpoint_type("/api/v1/users") == "api"
    assert classify_endpoint_type("/graphql") == "api"


def test_classifies_auth_marker():
    assert classify_endpoint_type("/account/login") == "auth"
    assert classify_endpoint_type("/signup") == "auth"


def test_classifies_admin_marker():
    assert classify_endpoint_type("/wp-admin/index.php") == "admin"
    assert classify_endpoint_type("/dashboard") == "admin"


def test_classifies_upload_marker():
    assert classify_endpoint_type("/media/upload") == "upload"


def test_classifies_page_for_extensionless_or_trailing_slash():
    assert classify_endpoint_type("/") == "page"
    assert classify_endpoint_type("/about/") == "page"
    assert classify_endpoint_type("/contact") == "page"
    assert classify_endpoint_type("/index.html") == "page"


def test_classifies_unknown_for_unrecognized_extension():
    assert classify_endpoint_type("/report.pdf") == "unknown"


def test_empty_or_none_input_is_unknown():
    assert classify_endpoint_type("") == "unknown"
    assert classify_endpoint_type(None) == "unknown"


def test_marker_priority_asset_before_api():
    # asset extension check happens before marker checks
    assert classify_endpoint_type("/api/v1/app.js") == "asset"
