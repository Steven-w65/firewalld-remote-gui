"""Portable Windows-first entry point for Remote firewalld Manager."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from app.config.config_manager import ConfigManager
from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
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


def main(argv: Sequence[str] | None = None) -> int:
    application = QApplication.instance()
    if application is None:
        application = QApplication(list(sys.argv if argv is None else argv))
    application.setApplicationName("Remote firewalld Manager")

    paths = PortablePaths.from_entrypoint(Path(__file__))
    config_manager = ConfigManager(paths.config_file)
    try:
        loaded = config_manager.load()
    except ConfigurationError:
        QMessageBox.critical(
            None,
            "Configuration Error",
            STARTUP_CONFIGURATION_MESSAGE,
        )
        return 2

    configure_logging(paths.log_dir, (server.password for server in loaded.servers))
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
        )

    controller = ServerController(
        _PreparedConfigManager(config_manager, loaded),
        scheduler,
        manager_factory,
        host_key_store=host_key_store,
    )
    window = MainWindow(controller)
    window.show()
    try:
        return application.exec()
    finally:
        window.shutdown_once()


if __name__ == "__main__":
    raise SystemExit(main())
