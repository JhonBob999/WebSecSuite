import json

import pytest

from core import session_persistence as persistence


def session_data():
    return persistence.build_scraper_session(tasks=[{
        "id": "saved", "url": "https://example.test", "params": {},
        "status": "Done", "result": {"title": "Unicode: Rīga"},
    }])


def test_atomic_save_round_trip(tmp_path):
    path = tmp_path / "sessions" / "session.json"
    data = session_data()
    persistence.save_session(path, data)
    assert persistence.load_session(path) == data
    assert list(path.parent.iterdir()) == [path]
    assert path.read_bytes().endswith(b"\n")


@pytest.mark.parametrize("failure", ["write", "sync", "replace"])
def test_failed_save_preserves_previous_file_and_removes_temp(tmp_path, monkeypatch, failure):
    path = tmp_path / "session.json"
    original = b'{"previous": "must survive"}\n'
    path.write_bytes(original)

    if failure == "write":
        def fail_dump(data, fh, **kwargs):
            fh.write('{"partial":')
            raise OSError("Simulated write failure")

        monkeypatch.setattr(persistence.json, "dump", fail_dump)
    else:
        import os

        def fail(*args):
            raise OSError("Simulated IO failure")

        monkeypatch.setattr(os, "fsync" if failure == "sync" else "replace", fail)

    with pytest.raises(OSError):
        persistence.save_session(path, session_data())
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_save_serialization_failure_preserves_previous_file(tmp_path, monkeypatch):
    path = tmp_path / "session.json"
    path.write_text("previous", encoding="utf-8")

    def fail(value):
        raise ValueError("Simulated serialization failure")

    monkeypatch.setattr(persistence, "_safe_json", fail)
    with pytest.raises(ValueError):
        persistence.save_session(path, {})
    assert path.read_text(encoding="utf-8") == "previous"
    assert list(tmp_path.iterdir()) == [path]


def test_save_syncs_closed_temp_in_destination_before_replace(tmp_path, monkeypatch):
    import os
    from pathlib import Path

    path = tmp_path / "session.json"
    real_sync, real_replace = os.fsync, os.replace
    synced = []

    def sync(fd):
        synced.append(True)
        real_sync(fd)

    def replace(source, target):
        assert Path(source).parent == tmp_path
        assert Path(source) != path
        assert synced
        assert json.loads(Path(source).read_text(encoding="utf-8")) == session_data()
        real_replace(source, target)

    data = session_data()
    # Stable timestamp for comparison inside replace.
    monkeypatch.setattr(persistence, "utc_timestamp", lambda: data["saved_at"])
    monkeypatch.setattr(os, "fsync", sync)
    monkeypatch.setattr(os, "replace", replace)
    persistence.save_session(path, data)
    assert persistence.load_session(path) == data


@pytest.mark.parametrize("params, expected", [
    ({"headers": {"User-Agent": "test", "Accept": "text/html"}}, False),
    ({"proxy": "http://proxy.test:8080"}, False),
    ({"cookie_file": "custom.json", "cookie_mode": "custom"}, False),
    ({"headers": {"authorization": "test-secret"}}, True),
    ({"headers": {"X-Auth": "test-secret"}}, True),
    ({"headers": {"X-Csrf-Token": "test-secret"}}, True),
    ({"headers": {"X-Session-ID": "test-secret"}}, True),
])
def test_sensitive_field_detection(params, expected):
    data = persistence.build_scraper_session(tasks=[{"params": params}])
    assert persistence.session_contains_sensitive_data(data) is expected


def test_sensitive_detection_includes_saved_request_evidence():
    data = persistence.build_scraper_session(tasks=[{
        "params": {}, "result": {"request_recipe": {"headers": {"Cookie": "test-secret"}}},
    }])
    assert persistence.session_contains_sensitive_data(data)
