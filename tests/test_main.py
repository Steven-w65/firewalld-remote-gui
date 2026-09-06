from __future__ import annotations

from types import SimpleNamespace

import pytest

import main
from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
from app.utils.errors import ConfigurationError


class FakeApplication:
    _instance = None

    def __init__(self, argv):
        self.argv = argv
        self.exec_calls = 0
        FakeApplication._instance = self

    @classmethod
    def instance(cls):
        return cls._instance

    def setApplicationName(self, name):
        self.application_name = name

    def exec(self):
        self.exec_calls += 1
        return 17


def loaded_config(password: str = "ssh-top-secret") -> LoadedConfig:
    return LoadedConfig(
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


def test_main_constructs_portable_dependencies_and_tears_down_once(
    monkeypatch, tmp_path
):
    FakeApplication._instance = None
    config_file = tmp_path / "config.yaml"
    known_hosts_file = tmp_path / "known_hosts"
    log_dir = tmp_path / "logs"
    paths = SimpleNamespace(
        root=tmp_path,
        config_file=config_file,
        known_hosts_file=known_hosts_file,
        log_dir=log_dir,
    )
    calls: dict[str, object] = {}

    class FakeConfigManager:
        def __init__(self, path):
            calls["config_path"] = path

        def load(self):
            calls["config_loads"] = int(calls.get("config_loads", 0)) + 1
            return loaded_config()

    class FakeController:
        def __init__(
            self,
            config_manager,
            scheduler,
            manager_factory,
            *,
            host_key_store,
        ):
            calls["controller"] = (
                config_manager,
                scheduler,
                manager_factory,
                host_key_store,
            )
            self.loaded = config_manager.load()

    class FakeWindow:
        def __init__(self, controller, firewall_controller):
            calls["window_controller"] = controller
            calls["window_firewall_controller"] = firewall_controller
            calls["window"] = self
            self.show_calls = 0
            self.shutdown_calls = 0

        def show(self):
            self.show_calls += 1

        def shutdown_once(self):
            self.shutdown_calls += 1
            return True

    monkeypatch.setattr(main, "QApplication", FakeApplication)
    monkeypatch.setattr(
        main.PortablePaths, "from_entrypoint", lambda path: paths
    )
    monkeypatch.setattr(main, "ConfigManager", FakeConfigManager)
    monkeypatch.setattr(
        main,
        "configure_logging",
        lambda directory, secrets: calls.update(
            log_dir=directory, logging_secrets=tuple(secrets)
        ),
    )
    monkeypatch.setattr(
        main, "OperationScheduler", lambda: calls.setdefault("scheduler", object())
    )
    monkeypatch.setattr(
        main, "HostKeyStore", lambda path: calls.setdefault("known_hosts", path)
    )
    monkeypatch.setattr(main, "ServerController", FakeController)
    monkeypatch.setattr(
        main,
        "FirewallController",
        lambda controller: calls.setdefault("firewall_controller", controller),
    )
    monkeypatch.setattr(main, "MainWindow", FakeWindow)

    exit_code = main.main(["remote-firewalld-manager"])

    controller = calls["window_controller"]
    assert calls["window_firewall_controller"] is controller
    window = calls["window"]
    assert exit_code == 17
    assert calls["config_path"] == config_file
    assert calls["known_hosts"] == known_hosts_file
    assert calls["log_dir"] == log_dir
    assert calls["logging_secrets"] == ("ssh-top-secret",)
    assert calls["config_loads"] == 1
    assert window.show_calls == 1
    assert window.shutdown_calls == 1
    server = controller.loaded.servers[0]
    _, _, manager_factory, controller_host_keys = calls["controller"]
    assert controller_host_keys == known_hosts_file
    monkeypatch.setattr(
        main,
        "SSHManager",
        lambda cfg, store, connect_timeout, command_timeout, *, client_factory: (
            cfg.id,
            store,
            connect_timeout,
            command_timeout,
            client_factory,
        ),
    )
    assert manager_factory(server, controller.loaded.application) == (
        "web01",
        known_hosts_file,
        4,
        9,
        main.paramiko.SSHClient,
    )


def test_invalid_configuration_shows_only_fixed_safe_startup_message(
    monkeypatch, tmp_path
):
    FakeApplication._instance = None
    secret = "ssh-do-not-display"
    paths = SimpleNamespace(
        root=tmp_path,
        config_file=tmp_path / "secret-config.yaml",
        known_hosts_file=tmp_path / "known_hosts",
        log_dir=tmp_path / "logs",
    )
    messages: list[tuple[object, str, str]] = []

    class BrokenConfigManager:
        def __init__(self, path):
            self.path = path

        def load(self):
            raise ConfigurationError(f"bad {self.path}: password={secret}")

    monkeypatch.setattr(main, "QApplication", FakeApplication)
    monkeypatch.setattr(
        main.PortablePaths, "from_entrypoint", lambda path: paths
    )
    monkeypatch.setattr(main, "ConfigManager", BrokenConfigManager)
    monkeypatch.setattr(
        main.QMessageBox,
        "critical",
        lambda parent, title, message: messages.append((parent, title, message)),
    )
    monkeypatch.setattr(
        main,
        "OperationScheduler",
        lambda: pytest.fail("scheduler must not be constructed"),
    )
    monkeypatch.setattr(
        main,
        "MainWindow",
        lambda controller: pytest.fail("window must not be constructed"),
    )

    exit_code = main.main([])

    assert exit_code == 2
    assert len(messages) == 1
    _, title, message = messages[0]
    assert title == "Configuration Error"
    assert message == main.STARTUP_CONFIGURATION_MESSAGE
    assert secret not in message
    assert str(paths.config_file) not in message
