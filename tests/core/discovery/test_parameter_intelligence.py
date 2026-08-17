from core.discovery.parameter_intelligence import analyze_query_params, classify_param_name


def test_classify_known_id_param():
    result = classify_param_name("user_id")
    assert result["category"] == "id"
    assert "sqli" in result["risk_tags"]
    assert "idor" in result["risk_tags"]
    assert result["confidence"] > 0.9


def test_classify_known_file_param():
    result = classify_param_name("template")
    assert result["category"] == "file"
    assert "lfi" in result["risk_tags"]


def test_classify_known_url_param():
    result = classify_param_name("redirect")
    assert result["category"] == "url"
    assert "ssrf" in result["risk_tags"]
    assert "open_redirect" in result["risk_tags"]


def test_classify_unknown_param():
    result = classify_param_name("totally_made_up_name")
    assert result["category"] == "unknown"
    assert result["risk_tags"] == []


def test_classify_empty_name_is_unknown_low_confidence():
    result = classify_param_name("")
    assert result["category"] == "unknown"
    assert result["confidence"] < 0.5


def test_analyze_query_params_empty_input():
    result = analyze_query_params({})
    assert result == {
        "params": [],
        "summary": {"total": 0, "by_category": {}, "high_risk": 0},
    }


def test_analyze_query_params_dict_input_deduplicates_case_insensitively():
    result = analyze_query_params({"id": ["1"], "ID": ["2"], "q": ["x"]})
    names = sorted(p["name"] for p in result["params"])
    assert names == ["id", "q"]
    assert result["summary"]["total"] == 2


def test_analyze_query_params_summary_counts_high_risk():
    result = analyze_query_params({"user_id": ["1"], "lang": ["en"]})
    assert result["summary"]["total"] == 2
    # user_id -> id category with risk_tags, lang -> lang category with no risk tags
    assert result["summary"]["high_risk"] == 1
    assert result["summary"]["by_category"] == {"id": 1, "lang": 1}


def test_analyze_query_params_accepts_list_of_names():
    result = analyze_query_params(["redirect", "next"])
    categories = {p["name"]: p["category"] for p in result["params"]}
    assert categories == {"redirect": "url", "next": "url"}
