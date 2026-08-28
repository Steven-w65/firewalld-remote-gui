from pathlib import Path

from app.paths import PortablePaths


def test_paths_are_anchored_to_main_file_not_cwd(tmp_path, monkeypatch):
    app_dir = tmp_path / "portable"
    entrypoint = app_dir / "main.py"
    elsewhere = tmp_path / "elsewhere"
    app_dir.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    paths = PortablePaths.from_entrypoint(entrypoint)

    assert paths.root == app_dir.resolve()
    assert paths.config_file == app_dir.resolve() / "config.yaml"
    assert paths.known_hosts_file == app_dir.resolve() / "known_hosts"
    assert paths.log_dir == app_dir.resolve() / "logs"
