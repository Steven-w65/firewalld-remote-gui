from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import main
from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
from app.paths import PortablePaths


def _paths(root):
    return PortablePaths.from_entrypoint(root / "main.py")


def _write_valid_config(root, password="startup-ssh-secret"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.yaml").write_text(
        "application:\n"
        "  ssh_timeout: 4\n"
        "  command_timeout: 9\n"
        "servers:\n"
        "  - id: web01\n"
        "    name: Production Web\n"
        "    host: web01.example.test\n"
        "    username: operator\n"
        f"    password: {password}\n"
        "    sudo: true\n",
        encoding="utf-8",
    )


def test_bootstrap_reports_missing_config_without_starting_connections(tmp_path):
    client_creations = []

    result = main.build_application(
        _paths(tmp_path), client_factory=lambda: client_creations.append(object())
    )

    assert not result.started
    assert result.safe_error == main.STARTUP_CONFIGURATION_MESSAGE
    assert "config.yaml" in result.safe_error
    assert client_creations == []
    assert result.shutdown()


@pytest.mark.parametrize(
    "body",
    (
        'servers:\n  - id: x\n    password: "startup-secret\n',
        "servers: [{id: x, password: startup-secret}]",
        "servers: [{id: x, name: X, host: host, username: user, "
        "password: startup-secret, sudo_password: sudo-secret}]",
    ),
)
def test_invalid_startup_configuration_never_discloses_file_contents(
    tmp_path, body
):
    (tmp_path / "config.yaml").write_text(body, encoding="utf-8")

    result = main.build_application(_paths(tmp_path))

    assert not result.started
    assert result.safe_error == main.STARTUP_CONFIGURATION_MESSAGE
    assert "startup-secret" not in result.safe_error
    assert "sudo-secret" not in result.safe_error
    assert str(tmp_path) not in result.safe_error


def test_non_utf8_configuration_returns_fixed_safe_error(tmp_path):
    (tmp_path / "config.yaml").write_bytes(
        b"servers:\n  - password: startup-secret-\xff\n"
    )

    result = main.build_application(_paths(tmp_path))

    assert not result.started
    assert result.safe_error == main.STARTUP_CONFIGURATION_MESSAGE
    assert "startup-secret" not in result.safe_error
    assert str(tmp_path) not in result.safe_error


def test_bootstrap_uses_main_directory_when_process_cwd_differs(
    tmp_path, monkeypatch, qapp
):
    app_dir = tmp_path / "portable"
    elsewhere = tmp_path / "elsewhere"
    _write_valid_config(app_dir)
    elsewhere.mkdir()
    (elsewhere / "config.yaml").write_text(
        "this is deliberately not the application config",
        encoding="utf-8",
    )
    monkeypatch.chdir(elsewhere)

    result = main.build_application(_paths(app_dir))
    try:
        assert result.started
        assert result.safe_error == ""
        assert (app_dir / "logs" / "remote-firewalld-manager.log").exists()
        assert not (elsewhere / "logs").exists()
    finally:
        assert result.shutdown()


def test_successful_bootstrap_builds_graph_without_creating_ssh_client(
    tmp_path, monkeypatch
):
    password = "bootstrap-redaction-secret"
    loaded = LoadedConfig(
        ApplicationConfig(ssh_timeout=4, command_timeout=9),
        (
            ServerConfig(
                "web01",
                "Production Web",
                "web01.example.test",
                "operator",
                password,
                sudo=True,
            ),
        ),
    )
    paths = _paths(tmp_path)
    calls = {}
    client_creations = []

    class FakeConfigManager:
        def __init__(self, path):
            calls["config_path"] = path

        def load(self):
            calls["loads"] = calls.get("loads", 0) + 1
            return loaded

    class FakeController:
        def __init__(
            self,
            config_manager,
            scheduler,
            manager_factory,
            *,
            host_key_store,
        ):
            calls["controller"] = self
            calls["scheduler"] = scheduler
            calls["manager_factory"] = manager_factory
            calls["controller_host_keys"] = host_key_store
            self.loaded = config_manager.load()
            self.shutdown_calls = []

        def shutdown(self, timeout_ms=5000):
            self.shutdown_calls.append(timeout_ms)
            return True

    class FakeWindow:
        def __init__(self, controller, firewall_controller):
            calls["window_controller"] = controller
            calls["window_firewall_controller"] = firewall_controller
            self.shutdown_calls = 0

        def shutdown_once(self):
            self.shutdown_calls += 1
            return calls["controller"].shutdown(timeout_ms=5000)

    monkeypatch.setattr(main, "ConfigManager", FakeConfigManager)
    monkeypatch.setattr(
        main,
        "configure_logging",
        lambda directory, secrets: calls.update(
            log_dir=directory, logging_secrets=tuple(secrets)
        ),
    )
    monkeypatch.setattr(
        main, "OperationScheduler", lambda: calls.setdefault("scheduler_object", object())
    )
    monkeypatch.setattr(
        main, "HostKeyStore", lambda path: calls.setdefault("host_key_path", path)
    )
    monkeypatch.setattr(main, "ServerController", FakeController)
    monkeypatch.setattr(
        main,
        "FirewallController",
        lambda controller: calls.setdefault("firewall_controller", object()),
    )
    monkeypatch.setattr(main, "MainWindow", FakeWindow)

    result = main.build_application(
        paths,
        client_factory=lambda: client_creations.append(object()),
    )

    assert result.started
    assert result.safe_error == ""
    assert calls["config_path"] == paths.config_file
    assert calls["log_dir"] == paths.log_dir
    assert calls["logging_secrets"] == (password,)
    assert calls["host_key_path"] == paths.known_hosts_file
    assert calls["loads"] == 1
    assert calls["window_controller"] is calls["controller"]
    assert calls["window_firewall_controller"] is calls["firewall_controller"]
    assert client_creations == []

    server = loaded.servers[0]
    manager = calls["manager_factory"](server, loaded.application)
    assert manager._client_factory() is None
    assert len(client_creations) == 1
    assert result.shutdown()
    assert result.shutdown()
    assert calls["controller"].shutdown_calls == [5000]


def test_bootstrap_cleans_controller_when_later_construction_fails(
    tmp_path, monkeypatch
):
    _write_valid_config(tmp_path)
    calls = {"shutdown": 0}

    class FakeController:
        def __init__(self, config_manager, scheduler, manager_factory, **kwargs):
            config_manager.load()

        def shutdown(self, timeout_ms=5000):
            calls["shutdown"] += 1
            calls["shutdown_timeout"] = timeout_ms
            return True

    monkeypatch.setattr(main, "ServerController", FakeController)
    monkeypatch.setattr(
        main,
        "FirewallController",
        lambda controller: (_ for _ in ()).throw(
            RuntimeError("password=construction-secret")
        ),
    )

    result = main.build_application(_paths(tmp_path))

    assert not result.started
    assert result.safe_error == main.STARTUP_FAILURE_MESSAGE
    assert "construction-secret" not in result.safe_error
    assert calls == {"shutdown": 1, "shutdown_timeout": 5000}
    assert result.shutdown()


def test_bootstrap_drains_scheduler_if_controller_construction_fails(
    tmp_path, monkeypatch
):
    _write_valid_config(tmp_path)
    scheduler = SimpleNamespace(wait_calls=[])
    scheduler.wait_for_done = lambda timeout: scheduler.wait_calls.append(timeout) or True
    monkeypatch.setattr(main, "OperationScheduler", lambda: scheduler)
    monkeypatch.setattr(
        main,
        "ServerController",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("broken graph")),
    )

    result = main.build_application(_paths(tmp_path))

    assert not result.started
    assert result.safe_error == main.STARTUP_FAILURE_MESSAGE
    assert scheduler.wait_calls == [5000]


def test_main_shows_one_safe_bootstrap_error_without_entering_event_loop(
    monkeypatch, qapp
):
    del qapp
    messages = []
    application = SimpleNamespace(
        setApplicationName=lambda name: None,
        exec=lambda: pytest.fail("event loop must not start"),
    )

    class FakeApplication:
        @classmethod
        def instance(cls):
            return application

    monkeypatch.setattr(main, "QApplication", FakeApplication)
    monkeypatch.setattr(
        main,
        "build_application",
        lambda paths: main.BootstrapResult.failure(main.STARTUP_CONFIGURATION_MESSAGE),
    )
    monkeypatch.setattr(
        main.QMessageBox,
        "critical",
        lambda parent, title, message: messages.append((parent, title, message)),
    )

    exit_code = main.main([])

    assert exit_code == 2
    assert messages == [
        (None, "Configuration Error", main.STARTUP_CONFIGURATION_MESSAGE)
    ]


def test_readme_distinguishes_repository_root_and_other_cwd_launches():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    use_section = readme.split("## Use", 1)[1].split("## Logs", 1)[0]

    assert "From the repository directory" in use_section
    assert "python main.py" in use_section
    assert "From another working directory" in use_section
    assert "a bare `python main.py` refers to the current directory" in use_section
    assert 'python "D:\\Tools\\firewalld-remote-gui\\main.py"' in use_section
