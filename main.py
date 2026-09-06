"""Portable Windows-first entry point for Remote firewalld Manager."""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import paramiko
from PySide6.QtWidgets import QApplication, QMessageBox

from app.config.config_manager import ConfigManager
from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.gui.main_window import MainWindow
from app.paths import PortablePaths
from app.ssh.host_keys import HostKeyStore
from app.ssh.ssh_manager import SSHManager
from app.utils.errors import ConfigurationError
from app.utils.logging_setup import configure_logging
from app.workers.scheduler import OperationScheduler


STARTUP_CONFIGURATION_MESSAGE = (
    "Unable to load the portable configuration. Check config.yaml and try again."
)
STARTUP_FAILURE_MESSAGE = (
    "Unable to start Remote firewalld Manager. Check the portable logs and try again."
)
_SHUTDOWN_TIMEOUT_MS = 5000


class _PreparedConfigManager:
    """Give the controller the validated initial load, then delegate reloads."""

    def __init__(self, manager: ConfigManager, loaded: LoadedConfig) -> None:
        self._manager = manager
        self._initial: LoadedConfig | None = loaded

    def load(self) -> LoadedConfig:
        if self._initial is not None:
            loaded = self._initial
            self._initial = None
            return loaded
        return self._manager.load()


@dataclass(slots=True)
class BootstrapResult:
    """Credential-free startup outcome with one bounded teardown boundary."""

    window: MainWindow | None = None
    safe_error: str = ""
    _shutdown_callback: Callable[[], bool] | None = field(
        default=None,
        repr=False,
    )
    _shutdown_complete: bool = field(default=False, init=False, repr=False)
    _shutdown_result: bool = field(default=True, init=False, repr=False)

    @property
    def started(self) -> bool:
        return self.window is not None and not self.safe_error

    @classmethod
    def success(cls, window: MainWindow) -> "BootstrapResult":
        return cls(window=window, _shutdown_callback=window.shutdown_once)

    @classmethod
    def failure(cls, safe_error: str) -> "BootstrapResult":
        return cls(safe_error=safe_error)

    def shutdown(self) -> bool:
        if self._shutdown_complete:
            return self._shutdown_result
        self._shutdown_complete = True
        if self._shutdown_callback is None:
            return True
        try:
            self._shutdown_result = bool(self._shutdown_callback())
        except Exception:
            self._shutdown_result = False
        return self._shutdown_result


def _cleanup_partial_startup(
    controller: ServerController | None,
    scheduler: OperationScheduler | None,
) -> None:
    if controller is not None:
        try:
            controller.shutdown(timeout_ms=_SHUTDOWN_TIMEOUT_MS)
            return
        except Exception:
            pass
    if scheduler is not None:
        try:
            scheduler.wait_for_done(_SHUTDOWN_TIMEOUT_MS)
        except Exception:
            pass


def build_application(
    paths: PortablePaths,
    client_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient,
) -> BootstrapResult:
    """Build the configured application graph without opening an SSH connection."""
    config_manager = ConfigManager(paths.config_file)
    try:
        loaded = config_manager.load()
    except (ConfigurationError, UnicodeError):
        return BootstrapResult.failure(STARTUP_CONFIGURATION_MESSAGE)

    scheduler: OperationScheduler | None = None
    controller: ServerController | None = None
    try:
        operation_logger = configure_logging(
            paths.log_dir,
            (server.password for server in loaded.servers),
        )
        scheduler = OperationScheduler()
        host_key_store = HostKeyStore(paths.known_hosts_file)

        def manager_factory(
            server: ServerConfig,
            application_config: ApplicationConfig,
        ) -> SSHManager:
            return SSHManager(
                server,
                host_key_store,
                connect_timeout=application_config.ssh_timeout,
                command_timeout=application_config.command_timeout,
                client_factory=client_factory,
            )

        controller = ServerController(
            _PreparedConfigManager(config_manager, loaded),
            scheduler,
            manager_factory,
            host_key_store=host_key_store,
            operation_logger=operation_logger,
        )
        firewall_controller = FirewallController(controller)
        window = MainWindow(controller, firewall_controller)
    except Exception:
        _cleanup_partial_startup(controller, scheduler)
        return BootstrapResult.failure(STARTUP_FAILURE_MESSAGE)

    return BootstrapResult.success(window)


def main(argv: Sequence[str] | None = None) -> int:
    application = QApplication.instance()
    if application is None:
        application = QApplication(list(sys.argv if argv is None else argv))
    application.setApplicationName("Remote firewalld Manager")

    result = build_application(PortablePaths.from_entrypoint(Path(__file__)))
    if not result.started:
        title = (
            "Configuration Error"
            if result.safe_error == STARTUP_CONFIGURATION_MESSAGE
            else "Startup Error"
        )
        QMessageBox.critical(
            None,
            title,
            result.safe_error,
        )
        return 2
    assert result.window is not None
    result.window.show()
    try:
        return application.exec()
    finally:
        result.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
