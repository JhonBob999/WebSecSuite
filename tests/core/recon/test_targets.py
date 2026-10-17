"""Offline target validation and import contracts."""

import importlib
from dataclasses import FrozenInstanceError

import pytest


def api():
    return importlib.import_module("core.recon.targets")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM", "example.com"),
        (" \tExample.COM.\r\n", "example.com"),
        ("\u00a0example.com", "example.com"),
        ("example.com\u3000", "example.com"),
        ("www.sub-domain.example.com", "www.sub-domain.example.com"),
        ("123.example", "123.example"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("BÜCHER.DE", "xn--bcher-kva.de"),
        ("XN--BCHER-KVA.DE.", "xn--bcher-kva.de"),
        ("faß.de", "xn--fa-hia.de"),
        ("\u0646\u0627\u0645\u0647\u200c\u0627\u06cc.ir", "xn--mgba3gch31f060k.ir"),
        ("\u0915\u094d\u200d\u0937\u093f\u0924\u093f.in", "xn--11b4a4c6ab4f685s.in"),
        ("ｅｘａｍｐｌｅ.com", "example.com"),
        ("a" * 63 + ".example", "a" * 63 + ".example"),
        (".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61]),
         ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])),
    ],
)
def test_normalizes_only_canonical_hostnames(value, expected):
    assert api().normalize_hostname(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "", " \t\r\n", ".", "example", "localhost", "--help", "-example.com",
        "example-.com", "example..com", ".example.com", "example.com..",
        "https://example.com", "http://example.com/path", "//example.com",
        "example.com/path", "example.com\\path", "example.com?x=1",
        "example.com#part", "example.com:443", "user@example.com",
        "user:pass@example.com", "*.example.com", "foo_bar.example.com",
        "127.0.0.1", "192.168.001.001", "::1", "[2001:db8::1]",
        "example.123", "example.１２３", "xn--.com", "xn--a.com",
        "bad name.com", "bad\tname.com", "bad\nname.com", "a\x00.example",
        "a\x1f.example", "exam\u200bple.com", "exam\u00adple.com",
        "exam\u034fple.com", "exam\ufeffple.com", "exam\u2028ple.com",
        "exam\u00a0ple.com", "exam\u3000ple.com", "exam\u200cple.com", "exam\u200dple.com",
        "example\u3002com", "example\uff0ecom", "example\uff61com",
        "ex\ud800ample.com", "a" * 64 + ".com",
        ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 62]),
        None, 42,
    ],
)
def test_rejects_invalid_or_ambiguous_hostnames_with_readable_reason(value):
    with pytest.raises(ValueError) as error:
        api().normalize_hostname(value)
    assert str(error.value).strip()
    assert "\n" not in str(error.value)
    assert "\r" not in str(error.value)


def test_text_import_deduplicates_and_supplies_safe_review_defaults():
    report = api().parse_text("Example.COM\nexample.com.\nbücher.de\nXN--BCHER-KVA.DE\n", "manual")
    assert [target.hostname for target in report.targets] == ["example.com", "xn--bcher-kva.de"]
    assert [target.source for target in report.targets] == ["manual", "manual"]
    assert all(target.selected is False for target in report.targets)
    assert all(target.validation_state == "Valid" for target in report.targets)
    assert all(target.scope_status == "Unreviewed" for target in report.targets)
    assert report.duplicates == 2
    assert report.issues == []


def test_text_import_keeps_physical_rows_for_blanks_and_invalid_values():
    report = api().parse_text("example.com\r\n\r\nhttps://bad.example\r\n good.example\r\n")
    assert [target.hostname for target in report.targets] == ["example.com", "good.example"]
    assert [(issue.row, issue.value) for issue in report.issues] == [(2, ""), (3, "https://bad.example")]
    assert all(issue.reason for issue in report.issues)
    assert all(target.source == "paste" for target in report.targets)


@pytest.mark.parametrize("text", ["", " ", "\t\r\n\n"])
def test_empty_text_import_is_empty(text):
    report = api().parse_text(text)
    assert (report.targets, report.issues, report.duplicates) == ([], [], 0)


def test_text_import_does_not_treat_unicode_line_separators_as_new_rows():
    report = api().parse_text("exam\u2028ple.com\ngood.example")
    assert [target.hostname for target in report.targets] == ["good.example"]
    assert len(report.issues) == 1
    assert report.issues[0].row == 1


def test_import_reports_have_independent_collections_and_immutable_issues():
    first = api().ImportReport()
    second = api().ImportReport()
    first.targets.append(api().TargetRecord("example.com", "paste"))
    first.issues.append(api().ImportIssue(1, "bad", "Invalid hostname"))
    assert second.targets == []
    assert second.issues == []
    with pytest.raises(FrozenInstanceError):
        first.issues[0].row = 2


def test_csv_columns_trims_bom_and_whitespace_without_guessing():
    assert api().csv_columns('\ufeff domain , owner \nexample.com,Alice\n') == ["domain", "owner"]
    assert api().csv_columns('\ufeff"domain",owner\nexample.com,Alice\n') == ["domain", "owner"]


@pytest.mark.parametrize("text", ["", "  \r\n\t"])
def test_empty_csv_columns_and_import_are_empty(text):
    assert api().csv_columns(text) == []
    report = api().parse_csv(text, "domain")
    assert (report.targets, report.issues, report.duplicates) == ([], [], 0)


@pytest.mark.parametrize("text", ["domain,domain\n", "domain, domain \n", "domain,\n", ",owner\n", '"domain,owner\n'])
def test_csv_columns_rejects_duplicate_empty_or_malformed_headers(text):
    with pytest.raises(ValueError) as error:
        api().csv_columns(text)
    assert str(error.value).strip()
    assert "\n" not in str(error.value)


def test_csv_import_uses_explicit_column_and_canonical_duplicate_detection():
    text = "owner, domain \nAlice,Example.COM\nBob,bücher.de\nCarol,example.com.\nDave,XN--BCHER-KVA.DE\n"
    report = api().parse_csv(text, "domain")
    assert [target.hostname for target in report.targets] == ["example.com", "xn--bcher-kva.de"]
    assert all(target.source == "csv" for target in report.targets)
    assert report.issues == []
    assert report.duplicates == 2


@pytest.mark.parametrize("column", ["absent", "DOMAIN", " domain ", ""])
def test_csv_import_requires_exact_header_selection(column):
    report = api().parse_csv("domain,owner\nexample.com,Alice\n", column)
    assert report.targets == []
    assert len(report.issues) == 1
    assert report.issues[0].row == 1
    assert "column" in report.issues[0].reason.lower()


def test_csv_import_keeps_invalid_structural_and_blank_row_numbers():
    text = "owner,domain\nAlice,example.com\nBob,\nCarol,good.example,extra\nDave\n\nEve,https://bad.example\nFrank,other.example\n"
    report = api().parse_csv(text, "domain")
    assert [target.hostname for target in report.targets] == ["example.com", "other.example"]
    assert [issue.row for issue in report.issues] == [3, 4, 5, 6, 7]
    assert all(issue.reason for issue in report.issues)
    assert "column" in report.issues[1].reason.lower()
    assert "column" in report.issues[2].reason.lower()


def test_csv_import_tracks_physical_rows_after_quoted_multiline_fields():
    text = 'owner,domain\n"Alice\nSmith",example.com\nBob,invalid\nCarol,good.example\n'
    report = api().parse_csv(text, "domain")
    assert [target.hostname for target in report.targets] == ["example.com", "good.example"]
    assert [issue.row for issue in report.issues] == [4]


def test_csv_import_rejects_multiline_hostnames_with_single_line_reason():
    report = api().parse_csv('domain\n"exam\nple.com"\ngood.example\n', "domain")
    assert [target.hostname for target in report.targets] == ["good.example"]
    assert report.issues[0].row == 2
    assert report.issues[0].value == "exam\nple.com"
    assert "\n" not in report.issues[0].reason


@pytest.mark.parametrize("text", ['domain,domain\nexample.com,other.example\n', 'domain,\nexample.com,Alice\n'])
def test_csv_import_reports_invalid_headers_instead_of_partial_import(text):
    report = api().parse_csv(text, "domain")
    assert report.targets == []
    assert len(report.issues) == 1
    assert report.issues[0].row == 1


@pytest.mark.parametrize("bad_row", ['"bad.example', '"bad.example"oops'])
def test_csv_import_reports_malformed_csv_and_preserves_prior_valid_rows(bad_row):
    report = api().parse_csv("domain\nexample.com\n" + bad_row, "domain")
    assert [target.hostname for target in report.targets] == ["example.com"]
    assert len(report.issues) == 1
    assert report.issues[0].row == 3
    assert "csv" in report.issues[0].reason.lower()


def test_csv_import_recovers_later_valid_rows_after_malformed_quoted_row():
    text = 'domain\nfirst.example\n"bad.example"oops\nlast.example\n'
    report = api().parse_csv(text, "domain")
    assert [target.hostname for target in report.targets] == ["first.example", "last.example"]
    assert len(report.issues) == 1
    assert report.issues[0].row == 3
    assert report.issues[0].value == '"bad.example"oops'


def test_csv_import_recovery_keeps_physical_range_of_malformed_multiline_row():
    text = 'domain\nfirst.example\n"bad\n.example"oops\nlast.example\n'
    report = api().parse_csv(text, "domain")
    assert [target.hostname for target in report.targets] == ["first.example", "last.example"]
    assert len(report.issues) == 1
    assert report.issues[0].row == 3
    assert report.issues[0].value == '"bad\n.example"oops'


def test_reads_utf8_bom_text_file_and_preserves_explicit_source(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("Example.COM\nexample.com.\nbad/path\n", encoding="utf-8-sig")
    report = api().read_target_file(path, source="TXT")
    assert [(target.hostname, target.source) for target in report.targets] == [("example.com", "TXT")]
    assert report.duplicates == 1
    assert [issue.row for issue in report.issues] == [3]


def test_reads_csv_file_with_explicit_source_and_column(tmp_path):
    path = tmp_path / "targets.CSV"
    path.write_text("owner,domain\nAlice,bücher.de\n", encoding="utf-8-sig")
    report = api().read_target_file(path, source="CSV upload", domain_column="domain")
    assert [(target.hostname, target.source) for target in report.targets] == [("xn--bcher-kva.de", "CSV upload")]
    assert report.issues == []


def test_csv_file_requires_column_selection(tmp_path):
    path = tmp_path / "targets.csv"
    path.write_text("domain\nexample.com\n", encoding="utf-8")
    report = api().read_target_file(path, source="CSV")
    assert report.targets == []
    assert len(report.issues) == 1
    assert "column" in report.issues[0].reason.lower()


@pytest.mark.parametrize("failure", ["missing", "invalid_utf8", "directory"])
def test_file_read_failures_are_reported_without_throwing(tmp_path, failure):
    path = tmp_path / "targets.txt"
    if failure == "invalid_utf8":
        path.write_bytes(b"\xff\xfeexample.com")
    elif failure == "directory":
        path.mkdir()
    report = api().read_target_file(path, source="TXT")
    assert report.targets == []
    assert len(report.issues) == 1
    assert report.issues[0].row == 0
    assert report.issues[0].reason
    assert "\n" not in report.issues[0].reason


def test_empty_csv_file_needs_no_column_selection(tmp_path):
    path = tmp_path / "targets.csv"
    path.write_text(" \n\t", encoding="utf-8-sig")
    report = api().read_target_file(path, source="CSV")
    assert (report.targets, report.issues, report.duplicates) == ([], [], 0)


@pytest.mark.parametrize("path", [r"\\server\share\targets.txt", "//server/share/targets.csv", "https://example.com/targets.txt"])
def test_rejects_remote_file_paths_without_opening_them(path, monkeypatch):
    def unexpected_read(*args, **kwargs):
        raise AssertionError("Remote paths must be rejected before file access")

    monkeypatch.setattr("pathlib.Path.read_text", unexpected_read)
    report = api().read_target_file(path, source="TXT")
    assert report.targets == []
    assert len(report.issues) == 1
    assert report.issues[0].row == 0
    assert "local" in report.issues[0].reason.lower()


def test_rejects_unsupported_file_extensions(tmp_path):
    path = tmp_path / "targets.json"
    path.write_text("example.com", encoding="utf-8")
    report = api().read_target_file(path, source="file")
    assert report.targets == []
    assert len(report.issues) == 1
    assert report.issues[0].row == 0


def test_read_target_text_decodes_local_utf8_bom(tmp_path):
    path = tmp_path / "targets.CSV"
    path.write_bytes(b"\xef\xbb\xbfdomain\nb\xc3\xbccher.de\n")
    assert api().read_target_text(path) == "domain\nbücher.de\n"


@pytest.mark.parametrize("path", [r"\\server\share\targets.txt", "//server/share/targets.csv", r"\/server/share/targets.txt", r"/\server/share/targets.txt", "https://example.com/targets.txt", "file://server/share/targets.txt"])
def test_read_target_text_rejects_remote_paths_before_file_access(path, monkeypatch):
    def unexpected_read(*args, **kwargs):
        raise AssertionError("Remote paths must be rejected before file access")

    monkeypatch.setattr("pathlib.Path.read_text", unexpected_read)
    with pytest.raises(ValueError, match="local"):
        api().read_target_text(path)


def test_read_target_text_rejects_unsupported_extensions_before_file_access(tmp_path, monkeypatch):
    def unexpected_read(*args, **kwargs):
        raise AssertionError("Unsupported formats must be rejected before file access")

    monkeypatch.setattr("pathlib.Path.read_text", unexpected_read)
    with pytest.raises(ValueError, match="TXT or CSV"):
        api().read_target_text(tmp_path / "targets.json")


def test_read_target_text_preserves_read_and_decode_errors(tmp_path):
    path = tmp_path / "targets.txt"
    with pytest.raises(OSError):
        api().read_target_text(path)
    path.write_bytes(b"\xffexample.com")
    with pytest.raises(UnicodeError):
        api().read_target_text(path)
