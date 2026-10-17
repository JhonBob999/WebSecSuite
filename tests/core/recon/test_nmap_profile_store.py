"""Offline profile persistence rejects whole invalid documents and preserves files."""

from dataclasses import replace
import json
from pathlib import Path

import pytest


def api():
    from core.recon import nmap_profile_store
    return nmap_profile_store


def custom(name="My web review"):
    from core.recon.nmap_profiles import BUILTIN_PROFILES, duplicate_profile
    return duplicate_profile(BUILTIN_PROFILES[0], name)


def document(*profiles):
    from core.recon.nmap_profiles import profile_to_dict
    return {"schema": "websecsuite.nmap.profiles", "version": 1,
            "profiles": [profile_to_dict(profile) for profile in profiles]}


def test_missing_file_loads_builtins_without_writing(tmp_path):
    from core.recon.nmap_profiles import BUILTIN_PROFILES
    path = tmp_path / "new" / "nmap_profiles.json"
    store = api().NmapProfileStore(path)
    assert store.profiles == ()
    assert store.all_profiles == BUILTIN_PROFILES
    assert store.writable and not store.load_error
    assert not path.parent.exists()


def test_roundtrip_rename_and_delete_preserve_identity(tmp_path):
    module = api()
    path = tmp_path / "profiles.json"
    store, profile = module.NmapProfileStore(path), custom()
    store.save(profile)
    reopened = module.NmapProfileStore(path)
    assert reopened.profiles == (profile,)
    renamed = replace(profile, name="Renamed profile")
    reopened.save(renamed)
    assert module.NmapProfileStore(path).profiles == (renamed,)
    reopened.delete(profile.profile_id)
    assert module.NmapProfileStore(path).profiles == ()


def test_saved_document_contains_only_allowlisted_configuration(tmp_path):
    path = tmp_path / "profiles.json"
    store, profile = api().NmapProfileStore(path), custom()
    store.save(profile)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data == document(profile)
    assert set(data["profiles"][0]) == {
        "profile_id", "name", "description", "is_builtin", "ports", "technique",
        "max_rate", "max_retries", "host_timeout_seconds", "execution_timeout_seconds",
        "version_detection", "network_impact",
    }


@pytest.mark.parametrize("raw", [b"{", b"\xff", b"[]", b"null", b'{"schema": 1}',
    b'{"schema":"websecsuite.nmap.profiles","version":2,"profiles":[]}',
    b'{"schema":"websecsuite.nmap.profiles","version":true,"profiles":[]}',
    b'{"schema":"websecsuite.nmap.profiles","version":1,"profiles":{},"target":"x"}',
    b'{"schema":"websecsuite.nmap.profiles","version":1,"profiles":[],"version":1}',
    b"[" * 1500 + b"]" * 1500,
])
def test_corrupt_or_unsupported_file_is_preserved_and_save_blocked(tmp_path, raw):
    path = tmp_path / "profiles.json"
    path.write_bytes(raw)
    store = api().NmapProfileStore(path)
    assert store.load_error and not store.writable
    assert not store.profiles
    assert len(store.all_profiles) == 4
    with pytest.raises(api().ProfileStorageError):
        store.save(custom())
    with pytest.raises(api().ProfileStorageError):
        store.delete("custom-test")
    assert path.read_bytes() == raw


@pytest.mark.parametrize("change", ["duplicate-id", "builtin", "builtin-id", "malformed", "secret", "grant"])
def test_complete_document_rejected_without_partial_load(tmp_path, change):
    from core.recon.nmap_profiles import BUILTIN_PROFILES, profile_to_dict
    first = custom()
    data = document(first, custom("Second"))
    if change == "duplicate-id":
        data["profiles"][1] = data["profiles"][0]
    elif change == "builtin":
        data["profiles"][1] = profile_to_dict(BUILTIN_PROFILES[0])
    elif change == "builtin-id":
        data["profiles"][1]["profile_id"] = "quick-network-discovery"
    elif change == "malformed":
        data["profiles"][1]["ports"] = "80,--script=all"
    elif change == "secret":
        data["profiles"][1]["credentials"] = "must not be accepted"
    else:
        data["profiles"][1]["scope_approval"] = True
    path = tmp_path / "profiles.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    store = api().NmapProfileStore(path)
    assert not store.profiles and store.load_error


def test_document_size_and_profile_count_bounds(tmp_path):
    module = api()
    path = tmp_path / "profiles.json"
    path.write_bytes(b" " * (module.MAX_PROFILE_DOCUMENT_BYTES + 1))
    assert module.NmapProfileStore(path).load_error
    data = document(*(custom() for _ in range(module.MAX_CUSTOM_PROFILES + 1)))
    path.write_text(json.dumps(data), encoding="utf-8")
    assert module.NmapProfileStore(path).load_error


def test_builtin_save_and_delete_are_rejected(tmp_path):
    from core.recon.nmap_profiles import BUILTIN_PROFILES
    store = api().NmapProfileStore(tmp_path / "profiles.json")
    with pytest.raises(api().ProfileStorageError):
        store.save(BUILTIN_PROFILES[0])
    with pytest.raises(api().ProfileStorageError):
        store.delete(BUILTIN_PROFILES[0].profile_id)
    assert not store.path.exists()


def test_atomic_replacement_failure_preserves_original_and_memory(tmp_path, monkeypatch):
    import os
    module = api()
    path, profile = tmp_path / "profiles.json", custom()
    store = module.NmapProfileStore(path)
    store.save(profile)
    original = path.read_bytes()

    def fail(source, target):
        assert Path(source).parent == path.parent
        assert Path(target) == path
        assert json.loads(Path(source).read_text(encoding="utf-8"))["profiles"][0]["name"] == "Changed"
        assert path.read_bytes() == original
        raise OSError("Replacement failed")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(module.ProfileStorageError):
        store.save(replace(profile, name="Changed"))
    assert store.profiles == (profile,)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_atomic_replace_uses_closed_complete_temporary_file(tmp_path, monkeypatch):
    import os
    path, profile = tmp_path / "profiles.json", custom()
    actual_replace = os.replace
    replacements = []

    def checked_replace(source, target):
        assert Path(source).parent == path.parent
        assert json.loads(Path(source).read_text(encoding="utf-8")) == document(profile)
        actual_replace(source, target)  # Windows also proves the writer closed the file.
        replacements.append(target)

    monkeypatch.setattr(os, "replace", checked_replace)
    api().NmapProfileStore(path).save(profile)
    assert replacements == [path]
    assert list(tmp_path.iterdir()) == [path]


def test_external_changes_are_never_silently_overwritten(tmp_path):
    path, profile = tmp_path / "profiles.json", custom()
    store = api().NmapProfileStore(path)
    store.save(profile)
    path.write_bytes(b"{broken externally")
    with pytest.raises(api().ProfileStorageError):
        store.save(replace(profile, name="Changed"))
    assert path.read_bytes() == b"{broken externally"
    assert store.profiles == (profile,)


def test_profile_count_limit_applies_before_writing(tmp_path):
    module = api()
    path = tmp_path / "profiles.json"
    profiles = [custom() for _ in range(module.MAX_CUSTOM_PROFILES)]
    path.write_text(json.dumps(document(*profiles)), encoding="utf-8")
    store = module.NmapProfileStore(path)
    assert not store.load_error
    original = path.read_bytes()
    with pytest.raises(module.ProfileStorageError):
        store.save(custom())
    assert path.read_bytes() == original and len(store.profiles) == module.MAX_CUSTOM_PROFILES


def test_default_path_uses_user_configuration_directory(monkeypatch, tmp_path):
    from PySide6.QtCore import QStandardPaths
    monkeypatch.setattr(QStandardPaths, "writableLocation", lambda kind: str(tmp_path))
    assert api().default_profile_path() == tmp_path / "WebSecSuite" / "nmap_profiles.json"
    assert not list(tmp_path.iterdir())


def test_competing_save_lock_preserves_file_and_allows_retry(tmp_path):
    from PySide6.QtCore import QLockFile
    path, profile = tmp_path / "profiles.json", custom()
    store = api().NmapProfileStore(path)
    lock = QLockFile(str(path) + ".lock")
    assert lock.tryLock(0)
    try:
        with pytest.raises(api().ProfileStorageError, match="another|Another"):
            store.save(profile)
        assert not path.exists() and store.profiles == ()
    finally:
        lock.unlock()
    store.save(profile)
    assert api().NmapProfileStore(path).profiles == (profile,)
    assert not Path(str(path) + ".lock").exists()


def test_stale_manager_rejects_another_managers_successful_save(tmp_path):
    path = tmp_path / "profiles.json"
    first, stale = api().NmapProfileStore(path), api().NmapProfileStore(path)
    profile = custom()
    first.save(profile)
    with pytest.raises(api().ProfileStorageError, match="changed"):
        stale.save(custom("Other manager"))
    assert api().NmapProfileStore(path).profiles == (profile,)
