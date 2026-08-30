"""Credential-safe presentation of typed domain and controller errors."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.controllers.server_controller import ControllerOperationError
from app.utils.errors import (
    ChangedHostKeyError,
    ConfigurationError,
    FirewallCommandError,
    FirewallParseError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
    HostKeyStoreError,
    PermissionDeniedError,
    SSHAuthenticationError,
    SSHError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    SystemProbeError,
    UnknownHostKeyError,
)


@dataclass(frozen=True, slots=True)
class _ErrorPresentation:
    title: str
    message: str
    severity: str


_CATEGORY_PRESENTATIONS = {
    "host_key_required": _ErrorPresentation(
        "SSH Host Key Confirmation Required",
        "Verify the server's SSH host key before connecting.",
        "warning",
    ),
    "host_key_changed": _ErrorPresentation(
        "SSH Host Key Changed",
        "The saved SSH host key no longer matches. Connection was blocked. "
        "Verify the server independently and repair the application's known_hosts "
        "file manually before reconnecting.",
        "critical",
    ),
    "ssh_authentication": _ErrorPresentation(
        "SSH Authentication Failed",
        "The server rejected the configured SSH credentials. Check the portable "
        "configuration and try again.",
        "error",
    ),
    "sudo_authentication": _ErrorPresentation(
        "Sudo Authentication Failed",
        "The sudo password was rejected and has been removed from session memory. "
        "Start the operation again to retry deliberately.",
        "error",
    ),
    "sudo_required": _ErrorPresentation(
        "Sudo Authentication Required",
        "This approved operation requires sudo authentication.",
        "warning",
    ),
    "permission": _ErrorPresentation(
        "Permission Denied",
        "The remote account is not authorized to perform this operation.",
        "error",
    ),
    "firewalld_missing": _ErrorPresentation(
        "Firewalld Not Installed",
        "Firewalld was not found on the selected server.",
        "error",
    ),
    "firewalld_stopped": _ErrorPresentation(
        "Firewalld Not Running",
        "Firewalld is installed but is not running on the selected server.",
        "warning",
    ),
    "ssh": _ErrorPresentation(
        "SSH Operation Failed",
        "The SSH operation failed. Reconnect and try again.",
        "error",
    ),
    "firewalld_output": _ErrorPresentation(
        "Invalid Firewalld Output",
        "The selected server returned firewall data that could not be safely read.",
        "error",
    ),
    "firewalld": _ErrorPresentation(
        "Firewalld Operation Failed",
        "The approved firewalld operation failed.",
        "error",
    ),
    "post_mutation_verification": _ErrorPresentation(
        "Reload Verification Incomplete",
        "Firewalld reloaded, but its running state could not be verified. "
        "Refresh or reconnect before making more changes.",
        "warning",
    ),
    "post_mutation_refresh": _ErrorPresentation(
        "Reload Completed; Refresh Failed",
        "Firewalld reloaded, but fresh firewall data could not be loaded. "
        "Existing firewall data is stale.",
        "warning",
    ),
    "system_probe": _ErrorPresentation(
        "System Probe Failed",
        "The remote system identity check failed.",
        "error",
    ),
    "operation": _ErrorPresentation(
        "Remote Operation Failed",
        "The remote operation failed.",
        "error",
    ),
    "host_key_store": _ErrorPresentation(
        "SSH Trust Store Error",
        "The application's known_hosts file could not be read or updated safely.",
        "error",
    ),
}


class ErrorDialog(QDialog):
    """Display only fixed copy selected by a typed, credential-free category."""

    def __init__(
        self, presentation: _ErrorPresentation, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.severity = presentation.severity
        self.setWindowTitle(presentation.title)
        self.setModal(True)

        self.message_label = QLabel(presentation.message)
        self.message_label.setWordWrap(True)
        self.message_label.setAccessibleName(f"{presentation.severity.title()} message")
        buttons = QDialogButtonBox()
        self.close_button = buttons.addButton(QDialogButtonBox.StandardButton.Close)
        self.close_button.setDefault(True)
        self.close_button.setAutoDefault(True)
        buttons.rejected.connect(self.reject)
        self.close_button.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.message_label)
        layout.addWidget(buttons)

    @classmethod
    def from_domain_error(
        cls, error: object, parent: QWidget | None = None
    ) -> ErrorDialog:
        if isinstance(error, ControllerOperationError):
            presentation = _CATEGORY_PRESENTATIONS.get(
                error.category, _CATEGORY_PRESENTATIONS["operation"]
            )
        elif isinstance(error, ChangedHostKeyError):
            presentation = _CATEGORY_PRESENTATIONS["host_key_changed"]
        elif isinstance(error, UnknownHostKeyError):
            presentation = _CATEGORY_PRESENTATIONS["host_key_required"]
        elif isinstance(error, ConfigurationError):
            presentation = _ErrorPresentation(
                "Configuration Error",
                "The portable configuration could not be loaded. Check config.yaml "
                "and try again.",
                "error",
            )
        elif isinstance(error, SSHAuthenticationError):
            presentation = _CATEGORY_PRESENTATIONS["ssh_authentication"]
        elif isinstance(error, SudoAuthenticationError):
            presentation = _CATEGORY_PRESENTATIONS["sudo_authentication"]
        elif isinstance(error, SudoAuthenticationRequiredError):
            presentation = _CATEGORY_PRESENTATIONS["sudo_required"]
        elif isinstance(error, PermissionDeniedError):
            presentation = _CATEGORY_PRESENTATIONS["permission"]
        elif isinstance(error, FirewalldNotInstalledError):
            presentation = _CATEGORY_PRESENTATIONS["firewalld_missing"]
        elif isinstance(error, FirewalldNotRunningError):
            presentation = _CATEGORY_PRESENTATIONS["firewalld_stopped"]
        elif isinstance(error, FirewallParseError):
            presentation = _CATEGORY_PRESENTATIONS["firewalld_output"]
        elif isinstance(error, FirewallCommandError):
            presentation = _CATEGORY_PRESENTATIONS["firewalld"]
        elif isinstance(error, SystemProbeError):
            presentation = _CATEGORY_PRESENTATIONS["system_probe"]
        elif isinstance(error, HostKeyStoreError):
            presentation = _CATEGORY_PRESENTATIONS["host_key_store"]
        elif isinstance(error, SSHError):
            presentation = _CATEGORY_PRESENTATIONS["ssh"]
        else:
            presentation = _CATEGORY_PRESENTATIONS["operation"]
        return cls(presentation, parent)

    def defaultButton(self) -> QPushButton:
        return self.close_button


__all__ = ["ErrorDialog"]
