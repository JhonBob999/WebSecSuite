from pathlib import Path

from core.paths import project_root


def test_project_root_points_to_repo_root():
    root = project_root()
    assert (root / "requirements.txt").is_file()
    assert (root / "core").is_dir()
    assert (root / "core" / "paths.py").is_file()


def test_project_root_is_independent_of_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert project_root() == Path(__file__).resolve().parents[2]
