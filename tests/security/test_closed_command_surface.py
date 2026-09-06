from __future__ import annotations

import re

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QComboBox,
    QLineEdit,
    QPlainTextEdit,
    QTextEdit,
)

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.controllers.session import ServerSessionView
from app.firewalld.lockout import LockoutRisk, RiskLevel
from app.gui.dialogs.add_port_dialog import AddPortDialog
from app.gui.dialogs.add_service_dialog import AddServiceDialog
from app.gui.dialogs.change_interface_dialog import ChangeInterfaceDialog
from app.gui.dialogs.confirmation_dialog import ConfirmationDialog
from app.gui.dialogs.error_dialog import ErrorDialog
from app.gui.dialogs.host_key_dialog import HostKeyDialog
from app.gui.dialogs.rich_rule_dialog import RichRuleDialog
from app.gui.dialogs.sudo_password_dialog import SudoPasswordDialog
from app.gui.interfaces_tab import InterfacesTab
from app.gui.logs_tab import LogsTab
from app.gui.main_window import MainWindow
from app.gui.models.interfaces_model import InterfacesTableModel
from app.gui.models.ports_model import PortsFilterProxyModel, PortsTableModel
from app.gui.models.rich_rules_model import RichRulesTableModel
from app.gui.models.services_model import ServicesFilterProxyModel, ServicesTableModel
from app.gui.models.zones_model import ZonesModel
from app.gui.overview_tab import OverviewTab
from app.gui.ports_tab import PortsTab
from app.gui.rich_rules_tab import RichRulesTab
from app.gui.services_tab import ServicesTab
from app.gui.zones_tab import ZonesTab
from app.models.change import ChangePreview
from app.models.enums import ApplyTarget, ConnectionStatus
from app.models.firewall import FirewallPort, FirewallSnapshot, RichRule, ZoneState
from app.ssh.host_keys import HostKeyChallenge
from app.utils.errors import SSHAuthenticationError


APPLICATION_SURFACE_TYPES = (
    MainWindow,
    ServerController,
    FirewallController,
    OverviewTab,
    PortsTab,
    ServicesTab,
    ZonesTab,
    InterfacesTab,
    RichRulesTab,
    LogsTab,
    AddPortDialog,
    AddServiceDialog,
    ChangeInterfaceDialog,
    RichRuleDialog,
    ConfirmationDialog,
    HostKeyDialog,
    SudoPasswordDialog,
    ErrorDialog,
    PortsTableModel,
    PortsFilterProxyModel,
    ServicesTableModel,
    ServicesFilterProxyModel,
    ZonesModel,
    InterfacesTableModel,
    RichRulesTableModel,
)


def _words(name: str) -> frozenset[str]:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return frozenset(value for value in separated.casefold().split("_") if value)


def _is_arbitrary_execution_surface(name: str) -> bool:
    words = _words(name)
    if words & {"execute", "exec", "run"}:
        return True
    if words & {"shell", "terminal"}:
        return True
    if "command" in words and words & {"open", "launch", "submit", "text"}:
        return True
    if words & {"file", "path"} and words & {
        "browse",
        "choose",
        "open",
        "read",
        "save",
        "write",
    }:
        return True
    return "raw" in words and bool(words & {"rich", "rule", "editor"})


def _application_owned_public_callables(*types: type) -> frozenset[str]:
    return frozenset(
        name
        for type_ in types
        for name in type_.__dict__
        if not name.startswith("_") and callable(getattr(type_, name, None))
    )


def _snapshot_with_unsupported_rule() -> FirewallSnapshot:
    supported = RichRule(
        'rule service name="ssh" accept', service="ssh", action="accept"
    )
    unsupported = RichRule(
        'rule family="ipv4" source address="192.0.2.0/24" log accept'
    )
    runtime = ZoneState(
        "public",
        interfaces=("eth0",),
        services=("ssh",),
        ports=(FirewallPort("22", "tcp", "public", True, False),),
        rich_rules=(supported, unsupported),
    )
    permanent = ZoneState(
        "public",
        interfaces=("eth0",),
        services=("ssh",),
        ports=(FirewallPort("22", "tcp", "public", False, True),),
        rich_rules=(supported, unsupported),
        permanent=True,
    )
    return FirewallSnapshot(
        hostname="web01",
        distribution="Acceptance Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(runtime, ZoneState("internal")),
        permanent_zones=(permanent, ZoneState("internal", permanent=True)),
        available_services=("http", "ssh"),
    )


def _connected_view() -> ServerSessionView:
    return ServerSessionView(
        server_id="web01",
        name="Production Web Server",
        host="web01.example.test",
        port=22,
        username="operator",
        sudo_enabled=True,
        generation=1,
        status=ConnectionStatus.CONNECTED,
        snapshot=_snapshot_with_unsupported_rule(),
        latest_error=None,
        busy_operation=None,
    )


def test_public_application_api_has_no_arbitrary_execution_or_file_entrypoint():
    for representative in (
        "execute",
        "run",
        "open_terminal",
        "execute_shell",
        "run_command",
        "open_command_text",
        "choose_file_path",
        "raw_rich_rule_editor",
    ):
        assert _is_arbitrary_execution_surface(representative)

    exposed = _application_owned_public_callables(*APPLICATION_SURFACE_TYPES)
    forbidden = tuple(
        sorted(name for name in exposed if _is_arbitrary_execution_surface(name))
    )
    assert forbidden == ()


def test_all_typed_dialogs_and_tabs_have_only_whitelisted_bounded_inputs(qtbot):
    tabs = {
        "overview": OverviewTab(),
        "ports": PortsTab(),
        "services": ServicesTab(),
        "zones": ZonesTab(),
        "interfaces": InterfacesTab(),
        "rich rules": RichRulesTab(),
        "logs": LogsTab(),
    }
    view = _connected_view()
    for name, tab in tabs.items():
        qtbot.addWidget(tab)
        if name == "logs":
            tab.set_server("web01")
            tab.set_entries(("safe acceptance log marker",))
        else:
            tab.set_session(view)

    port_dialog = AddPortDialog(("public", "internal"), "public")
    service_dialog = AddServiceDialog(
        ("http", "ssh"), ("public", "internal"), "public"
    )
    interface_dialog = ChangeInterfaceDialog(
        "eth0", "public", ("public", "internal")
    )
    rich_dialog = RichRuleDialog(
        ("public", "internal"), ("http", "ssh"), "public"
    )
    confirmation_dialog = ConfirmationDialog(
        ChangePreview(
            "Production Web Server",
            "web01.example.test",
            "Add Port",
            "public",
            "443/tcp",
            ApplyTarget.BOTH,
            LockoutRisk(RiskLevel.NONE, ("Detection remains incomplete.",)),
        )
    )
    host_key_dialog = HostKeyDialog(
        HostKeyChallenge(
            "web01.example.test",
            22,
            "ssh-ed25519",
            "SHA256:acceptance-fingerprint",
            object(),
        )
    )
    sudo_dialog = SudoPasswordDialog("Production Web Server")
    error_dialog = ErrorDialog.from_domain_error(SSHAuthenticationError("web01"))
    dialogs = {
        "add port": port_dialog,
        "add service": service_dialog,
        "change interface": interface_dialog,
        "structured rich rule": rich_dialog,
        "confirmation": confirmation_dialog,
        "host key": host_key_dialog,
        "sudo": sudo_dialog,
        "error": error_dialog,
    }
    for dialog in dialogs.values():
        qtbot.addWidget(dialog)

    roots = {**tabs, **dialogs}
    expected_inputs = {
        id(tabs["ports"].search_edit): "display-only port filter",
        id(tabs["services"].search_edit): "display-only service filter",
        id(port_dialog.port_edit): "validated port or range",
        id(rich_dialog.source_edit): "validated source network",
        id(rich_dialog.destination_edit): "validated destination network",
        id(rich_dialog.port_edit): "validated structured-rule port",
        id(sudo_dialog.password_edit): "masked session credential",
    }
    actual_inputs = []
    for surface_name, root in roots.items():
        for widget_type in (QLineEdit, QTextEdit, QPlainTextEdit):
            for widget in root.findChildren(widget_type):
                if not widget.isReadOnly():
                    actual_inputs.append((surface_name, widget))
    unexpected = tuple(
        (
            surface,
            type(widget).__name__,
            widget.accessibleName(),
            widget.placeholderText(),
        )
        for surface, widget in actual_inputs
        if id(widget) not in expected_inputs
    )
    missing = tuple(
        description
        for identity, description in expected_inputs.items()
        if all(id(widget) != identity for _surface, widget in actual_inputs)
    )
    assert unexpected == ()
    assert missing == ()

    for root in roots.values():
        assert all(not combo.isEditable() for combo in root.findChildren(QComboBox))
    assert tabs["logs"].text_view.isReadOnly()
    assert sudo_dialog.password_edit.echoMode() is QLineEdit.EchoMode.Password

    port_dialog.port_edit.setText("443; whoami")
    port_dialog.accept()
    assert port_dialog.request() is None
    rich_dialog.service_combo.setCurrentText("ssh")
    rich_dialog.source_edit.setText("192.0.2.1; whoami")
    rich_dialog.accept()
    assert rich_dialog.request() is None
    sudo_dialog.password_edit.setText("masked-input-probe")
    sudo_dialog.accept()
    assert sudo_dialog.take_password() == "masked-input-probe"
    assert not sudo_dialog.password_edit.text()

    tables = (
        tabs["overview"].test_results,
        tabs["ports"].table,
        tabs["services"].table,
        tabs["zones"].table,
        tabs["interfaces"].table,
        tabs["rich rules"].table,
    )
    for table in tables:
        assert table.editTriggers() is QAbstractItemView.EditTrigger.NoEditTriggers
        model = table.model()
        for row in range(model.rowCount()):
            for column in range(model.columnCount()):
                flags = model.flags(model.index(row, column))
                assert not flags & Qt.ItemFlag.ItemIsEditable

    rich_tab = tabs["rich rules"]
    unsupported_index = next(
        index for index, row in enumerate(rich_tab.rows()) if not row.supported
    )
    emitted = []
    rich_tab.remove_requested.connect(emitted.append)
    rich_tab.table.selectRow(unsupported_index)
    QApplication.processEvents()
    assert not rich_tab.remove_button.isEnabled()
    rich_tab.remove_button.click()
    assert emitted == []
