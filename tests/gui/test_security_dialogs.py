from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QDialog, QLabel, QLineEdit, QPushButton, QWidget

from app.controllers.server_controller import ControllerOperationError
from app.firewalld.lockout import LockoutRisk, RiskLevel
from app.gui.dialogs import (
    ChangePreview,
    ConfirmationDialog,
    ErrorDialog,
    HostKeyDialog,
    SudoPasswordDialog,
)
from app.models.enums import ApplyTarget
from app.utils.errors import (
    ChangedHostKeyError,
    ConfigurationError,
    SSHAuthenticationError,
    SudoAuthenticationError,
)


@pytest.fixture
def challenge():
    return SimpleNamespace(
        host="web01.example.test",
        port=2222,
        algorithm="ssh-ed25519",
        fingerprint_sha256="SHA256:safe-fingerprint",
    )


@pytest.fixture
def risky_preview():
    return ChangePreview(
        server_name="Production Web Server",
        host="web01.example.test",
        operation="Remove Firewall Port",
        zone="public",
        resource="22/tcp",
        target=ApplyTarget.BOTH,
        risk=LockoutRisk(
            RiskLevel.HIGH,
            ("This change may interrupt SSH access.",),
        ),
    )


def _widget_text(widget: QWidget) -> str:
    values: list[str] = []
    for child in (widget, *widget.findChildren(QWidget)):
        for getter_name in (
            "text",
            "title",
            "toolTip",
            "statusTip",
            "whatsThis",
            "accessibleName",
            "accessibleDescription",
        ):
            getter = getattr(child, getter_name, None)
            if callable(getter):
                value = getter()
                if isinstance(value, str):
                    values.append(value)
    return "\n".join(values)


def test_host_key_dialog_displays_sha256_and_requires_explicit_trust(
    qtbot, challenge
):
    dialog = HostKeyDialog(challenge)
    qtbot.addWidget(dialog)

    assert challenge.fingerprint_sha256 in dialog.fingerprint_label.text()
    assert challenge.algorithm in dialog.algorithm_label.text()
    assert dialog.defaultButton() is dialog.cancel_button
    assert not dialog.confirmed()

    dialog.trust_button.click()
    assert dialog.confirmed()


def test_closing_host_key_dialog_is_cancellation(qtbot, challenge):
    dialog = HostKeyDialog(challenge)
    qtbot.addWidget(dialog)

    dialog.close()

    assert not dialog.confirmed()


def test_sudo_password_is_removed_from_widget_when_taken(qtbot):
    dialog = SudoPasswordDialog("Production Web Server")
    qtbot.addWidget(dialog)
    dialog.password_edit.setText("sudo-secret")

    assert dialog.password_edit.echoMode() is QLineEdit.EchoMode.Password
    assert dialog.take_password() == "sudo-secret"
    assert dialog.password_edit.text() == ""
    assert "sudo-secret" not in _widget_text(dialog)


@pytest.mark.parametrize("close_method", ["reject", "close"])
def test_sudo_dialog_clears_password_on_every_cancel_path(qtbot, close_method):
    dialog = SudoPasswordDialog("Production Web Server")
    qtbot.addWidget(dialog)
    dialog.password_edit.setText("sudo-secret")

    getattr(dialog, close_method)()

    assert dialog.password_edit.text() == ""
    assert dialog.take_password() is None
    assert not dialog.confirmed()


def test_sudo_secret_never_enters_labels_properties_or_accessibility_text(qtbot):
    dialog = SudoPasswordDialog("Production Web Server")
    qtbot.addWidget(dialog)
    dialog.password_edit.setText("sudo-secret")

    for child in (dialog, *dialog.findChildren(QWidget)):
        assert "sudo-secret" not in child.accessibleName()
        assert "sudo-secret" not in child.accessibleDescription()
        assert "sudo-secret" not in child.toolTip()
        assert "sudo-secret" not in child.dynamicPropertyNames().__repr__()
    assert all(
        "sudo-secret" not in label.text()
        for label in dialog.findChildren(QLabel)
    )


def test_high_risk_confirmation_uses_apply_anyway_and_no_default_accept(
    qtbot, risky_preview
):
    dialog = ConfirmationDialog(risky_preview)
    qtbot.addWidget(dialog)

    assert dialog.apply_button.text() == "Apply Anyway"
    assert dialog.defaultButton() is dialog.cancel_button
    assert "22/tcp" in _widget_text(dialog)
    assert "Runtime + Permanent" in _widget_text(dialog)
    assert not dialog.confirmed()


def test_normal_confirmation_still_defaults_to_cancel(qtbot):
    preview = ChangePreview(
        server_name="Web",
        host="web01.example.test",
        operation="Add Firewall Port",
        zone="public",
        resource="8080/tcp",
        target=ApplyTarget.RUNTIME,
        risk=LockoutRisk(RiskLevel.NONE, ("Risk detection is incomplete.",)),
    )
    dialog = ConfirmationDialog(preview)
    qtbot.addWidget(dialog)

    assert dialog.apply_button.text() == "Apply"
    assert dialog.defaultButton() is dialog.cancel_button


@pytest.mark.parametrize(
    ("error", "expected_title", "expected_fragment", "expected_severity"),
    [
        (
            ControllerOperationError(
                "web01", "connect", "ssh_authentication", "unsafe-secret"
            ),
            "SSH Authentication Failed",
            "credentials",
            "error",
        ),
        (
            ConfigurationError("C:/secret/path config has password=unsafe-secret"),
            "Configuration Error",
            "portable configuration",
            "error",
        ),
        (
            ChangedHostKeyError(
                "secret-host", 22, "SHA256:old-secret", "SHA256:new-secret"
            ),
            "SSH Host Key Changed",
            "known_hosts",
            "critical",
        ),
        (
            SSHAuthenticationError("secret-server"),
            "SSH Authentication Failed",
            "credentials",
            "error",
        ),
        (
            SudoAuthenticationError("secret-server", "secret-operation"),
            "Sudo Authentication Failed",
            "session memory",
            "error",
        ),
        (
            ControllerOperationError(
                "web01",
                "reload_firewalld",
                "post_mutation_verification",
                "unsafe-secret raw verification error",
            ),
            "Reload Verification Incomplete",
            "could not be verified",
            "warning",
        ),
        (
            ControllerOperationError(
                "web01",
                "reload_firewalld",
                "post_mutation_refresh",
                "unsafe-secret raw refresh error",
            ),
            "Reload Completed; Refresh Failed",
            "data is stale",
            "warning",
        ),
    ],
)
def test_error_dialog_uses_only_fixed_sanitized_copy(
    qtbot, error, expected_title, expected_fragment, expected_severity
):
    dialog = ErrorDialog.from_domain_error(error)
    qtbot.addWidget(dialog)

    visible = _widget_text(dialog).lower()
    assert dialog.windowTitle() == expected_title
    assert expected_fragment in visible
    assert dialog.severity == expected_severity
    assert "unsafe-secret" not in visible
    assert "secret-host" not in visible
    assert "sha256:" not in visible


def test_changed_key_error_has_no_trust_or_replacement_action(qtbot):
    dialog = ErrorDialog.from_domain_error(
        ControllerOperationError(
            "web01", "connect", "host_key_changed", "unsafe raw detail"
        )
    )
    qtbot.addWidget(dialog)

    assert dialog.severity == "critical"
    assert "known_hosts" in _widget_text(dialog)
    assert all(
        "trust" not in button.text().lower()
        and "replace" not in button.text().lower()
        and "accept" not in button.text().lower()
        for button in dialog.findChildren(QPushButton)
    )
    assert dialog.defaultButton() is dialog.close_button


def test_port_post_mutation_refresh_error_uses_operation_specific_safe_copy(qtbot):
    """Catches reuse of reload-specific wording for a completed port mutation."""
    dialog = ErrorDialog.from_domain_error(
        ControllerOperationError(
            "web01",
            "add_port",
            "post_mutation_refresh",
            "unsafe-secret raw refresh detail",
        )
    )
    qtbot.addWidget(dialog)

    visible = _widget_text(dialog).lower()
    assert dialog.windowTitle() == "Port Change Completed; Refresh Failed"
    assert "port change completed" in visible
    assert "existing firewall data is stale" in visible
    assert "reload" not in visible
    assert "unsafe-secret" not in visible


@pytest.mark.parametrize(
    ("operation", "resource_title", "resource_message"),
    (
        ("reload_firewalld", "Reload", "Firewalld reloaded"),
        ("set_default_zone", "Default Zone Change", "default-zone change"),
        ("add_port", "Port Change", "port change"),
        ("remove_port", "Port Change", "port change"),
        ("add_service", "Service Change", "service change"),
        ("remove_service", "Service Change", "service change"),
        ("change_interface_zone", "Interface Zone Change", "interface-zone change"),
        ("add_rich_rule", "Rich Rule Change", "rich-rule change"),
        ("remove_rich_rule", "Rich Rule Change", "rich-rule change"),
    ),
)
@pytest.mark.parametrize(
    ("category", "title_suffix", "message_fragment"),
    (
        (
            "post_mutation_verification",
            "Verification Incomplete",
            "could not be verified",
        ),
        (
            "post_mutation_refresh",
            "Completed; Refresh Failed",
            "fresh firewall data could not be loaded",
        ),
    ),
)
def test_post_mutation_errors_use_fixed_operation_specific_copy(
    qtbot,
    operation,
    resource_title,
    resource_message,
    category,
    title_suffix,
    message_fragment,
):
    """Catches resource changes being falsely presented as firewalld reloads."""
    dialog = ErrorDialog.from_domain_error(
        ControllerOperationError(
            "web01",
            operation,
            category,
            "unsafe-secret raw backend detail",
        )
    )
    qtbot.addWidget(dialog)

    visible = _widget_text(dialog)
    assert dialog.windowTitle() == f"{resource_title} {title_suffix}"
    assert resource_message.casefold() in visible.casefold()
    assert message_fragment in visible.casefold()
    assert "unsafe-secret" not in visible
    if operation != "reload_firewalld":
        assert "reload" not in visible.casefold()


def test_dialogs_never_call_backend_objects(qtbot, challenge, risky_preview):
    for dialog in (
        HostKeyDialog(challenge),
        SudoPasswordDialog("Web"),
        ConfirmationDialog(risky_preview),
        ErrorDialog.from_domain_error(
            ControllerOperationError("web01", "refresh", "ssh", "ignored")
        ),
    ):
        qtbot.addWidget(dialog)
        assert not hasattr(dialog, "ssh_manager")
        assert not hasattr(dialog, "firewalld_service")
        assert not hasattr(dialog, "command_builder")
