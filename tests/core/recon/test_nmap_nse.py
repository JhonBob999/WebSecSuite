"""Installed NSE scripts are inert catalog records until explicit run approval."""

import importlib
from pathlib import Path

import pytest

from tests.core.recon.test_nmap_public_adapter import tool
from tests.core.recon.test_nmap_adapter import candidate


def api():
    return importlib.import_module("core.recon.nmap_nse")


def catalog(tool):
    directory = Path(tool.executable_path).parent / "scripts"
    directory.mkdir()
    (directory / "script.db").write_text('Entry { filename = "http-title.nse", categories = { "discovery", "safe", } }\n'
        'Entry { filename = "ssl-enum-ciphers.nse", categories = { "intrusive", "discovery", } }\n'
        'Entry { filename = "http-server-header.nse", categories = { "version", } }\n', encoding="utf-8")
    (directory / "http-title.nse").write_text('description = [[Read a title.]]\ncategories = {"safe", "discovery"}\n', encoding="utf-8")
    (directory / "ssl-enum-ciphers.nse").write_text('description = [[Disruptive fixture.]]\n', encoding="utf-8")
    (directory / "http-server-header.nse").write_text('description = [[Version fingerprint fixture.]]\n', encoding="utf-8")
    return directory


def test_installed_catalog_has_bound_script_hash_category_description(tool):
    directory = catalog(tool)
    scripts = api().discover_scripts(tool)
    title = next(item for item in scripts if item.script_id == "http-title")
    assert title.categories == ("discovery", "safe")
    assert title.description == "Read a title."
    assert title.path == str(directory / "http-title.nse") and len(title.sha256) == 64
    assert not title.high_impact
    assert next(item for item in scripts if item.script_id == "ssl-enum-ciphers").high_impact
    api().validate_scripts(tool, (title,))
    (directory / "http-title.nse").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError):
        api().validate_scripts(tool, (title,))


def test_catalog_never_accepts_arbitrary_path_or_missing_script(tool):
    directory = catalog(tool)
    (directory / "script.db").write_text('Entry { filename = "../outside.nse", categories = {"safe"} }', encoding="utf-8")
    with pytest.raises(ValueError):
        api().discover_scripts(tool)


@pytest.mark.parametrize("arguments", [(("target", "192.0.2.1"),), (("newtargets", "true"),),
    (("user", "admin"),), (("password", "secret"),), (("command", "calc"),),
    (("http.useragent", "a,b=c"),), (("http-title.redirects", "false"),),
    (("http.max-body-size", "999999999"),), (("unreviewed.setting", "1"),)])
def test_script_arguments_reject_credentials_scope_commands_and_unsafe_values(arguments):
    with pytest.raises(ValueError):
        api().validate_script_arguments(arguments)


def test_structured_script_arguments_have_a_small_documented_policy():
    arguments = (("http.max-body-size", "4096"), ("http.pipeline", "1"), ("http.useragent", "WebSecSuite"))
    assert api().validate_script_arguments(arguments) == arguments
