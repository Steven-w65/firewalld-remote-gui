"""Offline driver for the real Qt/controller application boundary."""

from __future__ import annotations

from dataclasses import dataclass, replace
import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QWidget,
)

from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.gui.dialogs.add_port_dialog import AddPortDialog
from app.gui.dialogs.add_service_dialog import AddServiceDialog
from app.gui.dialogs.change_interface_dialog import ChangeInterfaceDialog
from app.gui.dialogs.confirmation_dialog import ConfirmationDialog
from app.gui.dialogs.error_dialog import ErrorDialog
from app.gui.dialogs.rich_rule_dialog import RichRuleDialog
from app.gui.dialogs.sudo_password_dialog import SudoPasswordDialog
from app.gui.main_window import MainWindow
from app.models.command import CommandResult, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, TargetStatus
from app.models.firewall import FirewallPort, FirewallSnapshot, RichRule, ZoneState
from app.models.interface import InterfaceRow
from app.models.port import PortRow
from app.models.rich_rule import RichRuleRow
from app.models.service import ServiceRow
from app.utils.errors import (
    SSHAuthenticationError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
)
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
)


@dataclass(frozen=True, slots=True)
class OperationEvidence:
    """Credential-free proof that a driven write crossed its safety boundaries."""

    operation: str
    mutation_calls: int
    snapshot_refreshes: int
    confirmations: int


@dataclass(frozen=True, slots=True)
class CredentialSurfaceEvidence:
    """Immutable, secret-free capture of every public presentation sink."""

    logs: tuple[str, ...]
    errors: tuple[str, ...]
    clipboard: str
    widgets: tuple[str, ...]
    models: tuple[str, ...]
    sessions: tuple[str, ...]
    public_results: tuple[str, ...]
    sudo_prompted: bool
    sudo_reached_fake_service: bool
    sudo_widget_cleared: bool


def _management_rule() -> RichRule:
    return RichRule(
        'rule service name="ssh" accept',
        service="ssh",
        action="accept",
    )


def _snapshot(server_id: str) -> FirewallSnapshot:
    runtime_public = ZoneState(
        "public",
        interfaces=("eth0",),
        services=("ssh",),
        ports=(FirewallPort("22", "tcp", "public", True, False),),
        rich_rules=(_management_rule(),),
    )
    permanent_public = replace(
        runtime_public,
        ports=(FirewallPort("22", "tcp", "public", False, True),),
        permanent=True,
    )
    return FirewallSnapshot(
        hostname=server_id,
        distribution="Acceptance Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(runtime_public, ZoneState("internal")),
        permanent_zones=(permanent_public, ZoneState("internal", permanent=True)),
        available_services=("http", "https", "ssh"),
    )


def _target_result(
    target: ApplyTarget, execution: TargetStatus, verification: TargetStatus
) -> TargetResult:
    return TargetResult(target, execution, verification, None, "")


def _result(operation: str, target: ApplyTarget, *, partial: bool = False) -> CompositeOperationResult:
    permanent = runtime = None
    if target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH):
        permanent = _target_result(
            ApplyTarget.PERMANENT, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED
        )
    if target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH):
        status = TargetStatus.FAILED if partial else TargetStatus.SUCCEEDED
        verification = TargetStatus.NOT_RUN if partial else TargetStatus.SUCCEEDED
        runtime = _target_result(ApplyTarget.RUNTIME, status, verification)
    return CompositeOperationResult(operation, permanent=permanent, runtime=runtime)


def _replace_zone(
    snapshot: FirewallSnapshot,
    zone_name: str,
    *,
    permanent: bool,
    transform,
) -> FirewallSnapshot:
    attribute = "permanent_zones" if permanent else "runtime_zones"
    zones = getattr(snapshot, attribute)
    updated = tuple(transform(zone) if zone.name == zone_name else zone for zone in zones)
    return replace(snapshot, **{attribute: updated})


def _selected_proxy_row(table, source_model, predicate) -> None:
    for row_index in range(source_model.rowCount()):
        row = source_model.row_at(row_index)
        if row is not None and predicate(row):
            proxy = table.model()
            proxy_index = (
                proxy.mapFromSource(source_model.index(row_index, 0))
                if hasattr(proxy, "mapFromSource")
                else source_model.index(row_index, 0)
            )
            assert proxy_index.isValid()
            table.selectRow(proxy_index.row())
            return
    raise AssertionError("requested display row is absent")


def _set_combo_data(combo: QComboBox, value: object) -> None:
    for index in range(combo.count()):
        if combo.itemData(index) == value:
            combo.setCurrentIndex(index)
            return
    raise AssertionError(f"missing typed combo value: {value!r}")


def _widget_text(root: QWidget) -> tuple[str, ...]:
    values: list[str] = []
    for widget in (root, *root.findChildren(QWidget)):
        for getter in (
            widget.windowTitle,
            widget.accessibleName,
            widget.accessibleDescription,
            widget.toolTip,
        ):
            value = getter()
            if value:
                values.append(value)
        if hasattr(widget, "text"):
            value = widget.text()
            if value:
                values.append(value)
        if isinstance(widget, (QPlainTextEdit, QTextEdit)):
            values.append(widget.toPlainText())
        if isinstance(widget, QComboBox):
            values.extend(widget.itemText(index) for index in range(widget.count()))
        for name in widget.dynamicPropertyNames():
            try:
                value = widget.property(bytes(name).decode("utf-8", "replace"))
            except RuntimeError:
                # Qt owns internal values that do not always have Python converters.
                continue
            if value is not None:
                values.append(str(value))
    return tuple(values)


def _model_text(window: MainWindow) -> tuple[str, ...]:
    values: list[str] = []
    for tab in (
        window.overview_tab,
        window.ports_tab,
        window.services_tab,
        window.zones_tab,
        window.interfaces_tab,
        window.rich_rules_tab,
    ):
        table = getattr(tab, "table", getattr(tab, "test_results", None))
        model = None if table is None else table.model()
        if model is None:
            continue
        for row in range(model.rowCount()):
            for column in range(model.columnCount()):
                value = model.data(model.index(row, column), Qt.ItemDataRole.DisplayRole)
                if value:
                    values.append(str(value))
    return tuple(values)


class ApplicationHarnessFactory:
    def __init__(self, qtbot, monkeypatch) -> None:
        self._qtbot = qtbot
        self._monkeypatch = monkeypatch

    def with_servers(self, *server_ids: str) -> "ApplicationHarness":
        return ApplicationHarness(self._qtbot, self._monkeypatch, server_ids)

    def with_credentials(self, *, ssh: str, sudo: str) -> "ApplicationHarness":
        return ApplicationHarness(
            self._qtbot,
            self._monkeypatch,
            ("web01",),
            ssh_password=ssh,
            sudo_password=sudo,
        )


class ApplicationHarness:
    """Drive real widgets/controllers while keeping fake adapters test-private."""

    def __init__(
        self,
        qtbot,
        monkeypatch,
        server_ids: tuple[str, ...],
        *,
        ssh_password: str | None = None,
        sudo_password: str | None = None,
    ) -> None:
        if not server_ids:
            raise ValueError("at least one server is required")
        servers = tuple(
            ServerConfig(
                id=server_id,
                name={
                    "web01": "Production Web Server",
                    "db01": "Database Server",
                    "test01": "Test Server",
                }.get(server_id, server_id),
                host=f"{server_id}.example.test",
                username="operator",
                password=ssh_password or f"credential-for-{server_id}",
                port=22,
                sudo=True,
            )
            for server_id in server_ids
        )
        self._qtbot = qtbot
        self._monkeypatch = monkeypatch
        self._ssh_password = ssh_password
        self._sudo_password = sudo_password
        self._snapshots = {server_id: _snapshot(server_id) for server_id in server_ids}
        self._scheduler = ManualScheduler()
        self._managers = ManagerFactory()
        self._services = ServiceFactory()
        self._services.next_snapshots.update(self._snapshots)
        self._server = ServerController(
            FakeConfigManager(LoadedConfig(ApplicationConfig(), servers)),
            self._scheduler,
            self._managers,
            self._services,
        )
        self._firewall = FirewallController(self._server)
        self._window = MainWindow(self._server, self._firewall)
        self._qtbot.addWidget(self._window)
        self._confirmations: list[tuple[str, ...]] = []
        self._errors: list[tuple[str, ...]] = []
        self._public_results: list[str] = []
        self._evidence: list[OperationEvidence] = []
        self._sudo_dialogs: list[SudoPasswordDialog] = []
        self._firewall.operation_result.connect(
            lambda _server_id, result: self._public_results.append(repr(result))
        )

        def capture_error(dialog: ErrorDialog) -> int:
            self._errors.append(_widget_text(dialog))
            dialog.reject()
            return int(QDialog.DialogCode.Rejected)

        self._monkeypatch.setattr(ErrorDialog, "exec", capture_error)

    def server_ids(self) -> tuple[str, ...]:
        return self._window.server_sidebar.server_ids()

    def selected_server_id(self) -> str | None:
        return self._server.selected_server_id

    def connect(self, server_id: str) -> None:
        self.select(server_id)
        self._window.server_sidebar.connect_button.click()
        self._scheduler.pending(server_id, "connect").run_synchronously_for_test()

    def select(self, server_id: str) -> None:
        self._window.server_sidebar.select_server(server_id)
        QApplication.processEvents()

    def refresh(self, server_id: str) -> None:
        self.select(server_id)
        self._service(server_id).next_snapshot = self._snapshots[server_id]
        self._window.refresh_action.trigger()
        self._scheduler.pending(server_id, "refresh").run_synchronously_for_test()

    def add_port(
        self,
        server_id: str,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        partial: bool = False,
    ) -> None:
        self.select(server_id)
        current = self._snapshots[server_id]
        updated = current
        for permanent, selected in (
            (True, target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH)),
            (False, target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH) and not partial),
        ):
            if selected:
                updated = _replace_zone(
                    updated,
                    zone,
                    permanent=permanent,
                    transform=lambda value, p=permanent: replace(
                        value,
                        ports=value.ports
                        + (FirewallPort(port, protocol, zone, not p, p),),
                    ),
                )
        self._install_add_port_dialog(zone, port, protocol, target)
        self._install_confirmation()
        service = self._service(server_id)
        before_calls = len(service.add_port_calls)
        before_loads = len(service.load_calls)
        before_confirmations = len(self._confirmations)
        service.next_add_port_result = _result("add_port", target, partial=partial)
        service.next_snapshot = updated
        self._window.ports_tab.add_button.click()
        self._scheduler.pending(server_id, "add_port").run_synchronously_for_test()
        self._snapshots[server_id] = updated
        self._evidence.append(
            OperationEvidence(
                "add_port",
                len(service.add_port_calls) - before_calls,
                len(service.load_calls) - before_loads,
                len(self._confirmations) - before_confirmations,
            )
        )

    def remove_port(
        self,
        server_id: str,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
    ) -> None:
        self.select(server_id)
        current = self._snapshots[server_id]
        updated = current
        for permanent, selected in (
            (True, target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH)),
            (False, target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH)),
        ):
            if selected:
                updated = _replace_zone(
                    updated,
                    zone,
                    permanent=permanent,
                    transform=lambda value: replace(
                        value,
                        ports=tuple(
                            item
                            for item in value.ports
                            if (item.port, item.protocol) != (port, protocol)
                        ),
                    ),
                )
        self._install_confirmation()
        service = self._service(server_id)
        before_calls = len(service.remove_port_calls)
        before_loads = len(service.load_calls)
        before_confirmations = len(self._confirmations)
        service.next_remove_port_result = _result("remove_port", target)
        service.next_snapshot = updated
        _selected_proxy_row(
            self._window.ports_tab.table,
            self._window.ports_tab.source_model,
            lambda row: row.zone == zone
            and row.port == port
            and row.protocol == protocol,
        )
        self._window.ports_tab.remove_button.click()
        self._scheduler.pending(server_id, "remove_port").run_synchronously_for_test()
        self._snapshots[server_id] = updated
        self._evidence.append(
            OperationEvidence(
                "remove_port",
                len(service.remove_port_calls) - before_calls,
                len(service.load_calls) - before_loads,
                len(self._confirmations) - before_confirmations,
            )
        )

    def port_row(self, server_id: str, port: str, protocol: str) -> PortRow | None:
        self.select(server_id)
        for index in range(self._window.ports_tab.source_model.rowCount()):
            row = self._window.ports_tab.source_model.row_at(index)
            if row is not None and (row.port, row.protocol) == (port, protocol):
                return row
        return None

    def add_service(
        self, server_id: str, zone: str, service_name: str, target: ApplyTarget
    ) -> None:
        self.select(server_id)
        updated = self._snapshots[server_id]
        for permanent, selected in (
            (True, target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH)),
            (False, target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH)),
        ):
            if selected:
                updated = _replace_zone(
                    updated,
                    zone,
                    permanent=permanent,
                    transform=lambda value: replace(
                        value, services=value.services + (service_name,)
                    ),
                )
        self._install_add_service_dialog(zone, service_name, target)
        self._install_confirmation()
        service = self._service(server_id)
        service.next_add_service_result = _result("add_service", target)
        service.next_snapshot = updated
        self._window.services_tab.add_button.click()
        self._scheduler.pending(server_id, "add_service").run_synchronously_for_test()
        self._snapshots[server_id] = updated

    def remove_service(
        self, server_id: str, zone: str, service_name: str, target: ApplyTarget
    ) -> None:
        self.select(server_id)
        updated = self._snapshots[server_id]
        for permanent, selected in (
            (True, target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH)),
            (False, target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH)),
        ):
            if selected:
                updated = _replace_zone(
                    updated,
                    zone,
                    permanent=permanent,
                    transform=lambda value: replace(
                        value,
                        services=tuple(item for item in value.services if item != service_name),
                    ),
                )
        self._install_confirmation()
        service = self._service(server_id)
        service.next_remove_service_result = _result("remove_service", target)
        service.next_snapshot = updated
        _selected_proxy_row(
            self._window.services_tab.table,
            self._window.services_tab.source_model,
            lambda row: row.zone == zone and row.name == service_name,
        )
        self._window.services_tab.remove_button.click()
        self._scheduler.pending(server_id, "remove_service").run_synchronously_for_test()
        self._snapshots[server_id] = updated

    def service_row(self, server_id: str, service_name: str) -> ServiceRow | None:
        self.select(server_id)
        return next(
            (row for row in self._window.services_tab.inventory_rows() if row.name == service_name),
            None,
        )

    def set_default_zone(self, server_id: str, zone: str) -> None:
        self.select(server_id)
        updated = replace(self._snapshots[server_id], default_zone=zone)
        self._install_confirmation()
        service = self._service(server_id)
        service.next_set_default_zone_result = _result("set_default_zone", ApplyTarget.BOTH)
        service.next_snapshot = updated
        self._window.zones_tab.default_zone_combo.setCurrentText(zone)
        self._window.zones_tab.set_default_button.click()
        self._scheduler.pending(server_id, "set_default_zone").run_synchronously_for_test()
        self._snapshots[server_id] = updated

    def zone_names(self, server_id: str) -> tuple[str, ...]:
        self.select(server_id)
        return tuple(
            row.name for row in self._window.zones_tab.model.zones()
        )

    def change_interface(self, server_id: str, interface: str, new_zone: str) -> None:
        self.select(server_id)
        updated = self._snapshots[server_id]
        for permanent in (True, False):
            attribute = "permanent_zones" if permanent else "runtime_zones"
            zones = []
            for zone in getattr(updated, attribute):
                interfaces = tuple(item for item in zone.interfaces if item != interface)
                if zone.name == new_zone:
                    interfaces += (interface,)
                zones.append(replace(zone, interfaces=interfaces))
            updated = replace(updated, **{attribute: tuple(zones)})
        self._install_interface_dialog(new_zone)
        self._install_confirmation()
        service = self._service(server_id)
        service.next_change_interface_zone_result = _result(
            "change_interface_zone", ApplyTarget.BOTH
        )
        service.next_snapshot = updated
        _selected_proxy_row(
            self._window.interfaces_tab.table,
            self._window.interfaces_tab.model,
            lambda row: row.name == interface,
        )
        self._window.interfaces_tab.change_button.click()
        self._scheduler.pending(
            server_id, "change_interface_zone"
        ).run_synchronously_for_test()
        self._snapshots[server_id] = updated

    def interface_row(self, server_id: str, interface: str) -> InterfaceRow | None:
        self.select(server_id)
        return next(
            (row for row in self._window.interfaces_tab.rows() if row.name == interface),
            None,
        )

    def add_rich_rule(
        self,
        server_id: str,
        zone: str,
        service_name: str,
        target: ApplyTarget,
    ) -> None:
        self.select(server_id)
        rule = RichRule(
            f'rule service name="{service_name}" accept',
            service=service_name,
            action="accept",
        )
        updated = self._snapshots[server_id]
        for permanent, selected in (
            (True, target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH)),
            (False, target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH)),
        ):
            if selected:
                updated = _replace_zone(
                    updated,
                    zone,
                    permanent=permanent,
                    transform=lambda value: replace(
                        value, rich_rules=value.rich_rules + (rule,)
                    ),
                )
        self._install_rich_rule_dialog(zone, service_name, target)
        self._install_confirmation()
        service = self._service(server_id)
        service.next_add_rich_rule_result = _result("add_rich_rule", target)
        service.next_snapshot = updated
        self._window.rich_rules_tab.add_button.click()
        self._scheduler.pending(server_id, "add_rich_rule").run_synchronously_for_test()
        self._snapshots[server_id] = updated

    def remove_rich_rule(
        self, server_id: str, zone: str, service_name: str, target: ApplyTarget
    ) -> None:
        self.select(server_id)
        updated = self._snapshots[server_id]
        for permanent, selected in (
            (True, target in (ApplyTarget.PERMANENT, ApplyTarget.BOTH)),
            (False, target in (ApplyTarget.RUNTIME, ApplyTarget.BOTH)),
        ):
            if selected:
                updated = _replace_zone(
                    updated,
                    zone,
                    permanent=permanent,
                    transform=lambda value: replace(
                        value,
                        rich_rules=tuple(
                            rule for rule in value.rich_rules if rule.service != service_name
                        ),
                    ),
                )
        self._install_confirmation()
        service = self._service(server_id)
        service.next_remove_rich_rule_result = _result("remove_rich_rule", target)
        service.next_snapshot = updated
        _selected_proxy_row(
            self._window.rich_rules_tab.table,
            self._window.rich_rules_tab.model,
            lambda row: row.zone == zone and row.rule.service == service_name,
        )
        self._window.rich_rules_tab.remove_button.click()
        self._scheduler.pending(server_id, "remove_rich_rule").run_synchronously_for_test()
        self._snapshots[server_id] = updated

    def rich_rule_row(self, server_id: str, service_name: str) -> RichRuleRow | None:
        self.select(server_id)
        return next(
            (row for row in self._window.rich_rules_tab.rows() if row.rule.service == service_name),
            None,
        )

    def reload(self, server_id: str) -> None:
        self.select(server_id)
        self._install_confirmation()
        service = self._service(server_id)
        service.next_snapshot = self._snapshots[server_id]
        self._window.overview_tab.reload_button.click()
        self._scheduler.pending(server_id, "reload_firewalld").run_synchronously_for_test()

    def fail_next_ssh_authentication(self, server_id: str) -> None:
        self._managers.next_errors[server_id] = SSHAuthenticationError(server_id)
        self.connect(server_id)

    def simulate_auth_and_sudo_failures(self) -> CredentialSurfaceEvidence:
        server_id = self.server_ids()[0]
        assert self._ssh_password is not None
        assert self._sudo_password is not None

        self.fail_next_ssh_authentication(server_id)
        self.select(server_id)
        self._window.server_sidebar.connect_button.click()
        self._scheduler.pending(server_id, "reconnect").run_synchronously_for_test()
        service = self._service(server_id)
        tainted = CommandResult(
            False,
            1,
            self._ssh_password,
            self._sudo_password,
            server_id,
            "add_port",
            0.1,
        )
        service.next_add_port_result = CompositeOperationResult(
            "add_port",
            permanent=TargetResult(
                ApplyTarget.PERMANENT,
                TargetStatus.SUCCEEDED,
                TargetStatus.SUCCEEDED,
                tainted,
                self._ssh_password,
            ),
            runtime=TargetResult(
                ApplyTarget.RUNTIME,
                TargetStatus.FAILED,
                TargetStatus.NOT_RUN,
                tainted,
                self._sudo_password,
            ),
        )
        service.next_add_port_error = SudoAuthenticationRequiredError(
            server_id, "add_port"
        )
        partial_snapshot = _replace_zone(
            self._snapshots[server_id],
            "public",
            permanent=True,
            transform=lambda zone: replace(
                zone,
                ports=zone.ports
                + (FirewallPort("9443", "tcp", "public", False, True),),
            ),
        )
        service.next_snapshot = partial_snapshot
        self._install_add_port_dialog(
            "public", "9443", "tcp", ApplyTarget.BOTH
        )
        self._install_confirmation()
        self._install_sudo_dialog()
        self._window.ports_tab.add_button.click()
        self._scheduler.pending(server_id, "add_port").run_synchronously_for_test()
        self._scheduler.pending(server_id, "add_port").run_synchronously_for_test()
        self._snapshots[server_id] = partial_snapshot

        self._window.logs_tab.copy_button.click()
        service_received_sudo = bool(
            len(service.add_port_calls) >= 2
            and service.add_port_calls[-2][-1] is None
            and service.add_port_calls[-1][-1] == self._sudo_password
            and service.load_calls
            and service.load_calls[-1] == self._sudo_password
        )
        return CredentialSurfaceEvidence(
            logs=self._server.log_entries(server_id),
            errors=tuple(value for group in self._errors for value in group),
            clipboard=QApplication.clipboard().text(),
            widgets=tuple(
                value
                for root in (self._window, *self._sudo_dialogs)
                for value in _widget_text(root)
            ),
            models=_model_text(self._window),
            sessions=tuple(repr(view) for view in self._server.sessions()),
            public_results=tuple(self._public_results),
            sudo_prompted=bool(self._sudo_dialogs),
            sudo_reached_fake_service=service_received_sudo,
            sudo_widget_cleared=bool(self._sudo_dialogs)
            and all(not dialog.password_edit.text() for dialog in self._sudo_dialogs),
        )

    def simulate_later_sudo_authentication_failure(self) -> str:
        server_id = self.server_ids()[0]
        service = self._service(server_id)
        before_errors = len(self._errors)
        service.next_add_port_error = SudoAuthenticationError(server_id, "add_port")
        self._install_add_port_dialog("public", "8443", "tcp", ApplyTarget.BOTH)
        self._install_confirmation()
        self._window.ports_tab.add_button.click()
        self._scheduler.pending(server_id, "add_port").run_synchronously_for_test()
        return "\n".join(
            value for group in self._errors[before_errors:] for value in group
        )

    def confirmation_text(self) -> str:
        return "\n".join(self._confirmations[-1]) if self._confirmations else ""

    def last_operation_evidence(self) -> OperationEvidence | None:
        return self._evidence[-1] if self._evidence else None

    def visible_text(self) -> str:
        clipboard = QApplication.clipboard().text()
        values = [*_widget_text(self._window), *_model_text(self._window), clipboard]
        return "\n".join(values)

    def error_text(self) -> str:
        public_views = tuple(repr(view) for view in self._server.sessions())
        return "\n".join(
            (
                *(value for group in self._errors for value in group),
                *public_views,
                *self._public_results,
            )
        )

    def actionable_texts(self) -> tuple[str, ...]:
        values: list[str] = []
        widgets = [
            *self._window.findChildren(QPushButton),
            *self._window.findChildren(QLineEdit),
        ]
        for widget in widgets:
            values.extend(
                value
                for value in (
                    widget.text(),
                    widget.accessibleName(),
                    widget.toolTip(),
                    widget.placeholderText() if isinstance(widget, QLineEdit) else "",
                )
                if value
            )
        return tuple(values)

    def editable_field_descriptors(self) -> tuple[str, ...]:
        values = []
        widgets = [
            *self._window.findChildren(QLineEdit),
            *self._window.findChildren(QTextEdit),
            *self._window.findChildren(QPlainTextEdit),
        ]
        for widget in widgets:
            if hasattr(widget, "isReadOnly") and not widget.isReadOnly():
                values.append(
                    " | ".join(
                        filter(
                            None,
                            (
                                widget.accessibleName(),
                                widget.placeholderText()
                                if isinstance(widget, QLineEdit)
                                else "",
                            ),
                        )
                    )
                )
        return tuple(values)

    def _service(self, server_id: str):
        return self._services.instances[server_id][-1]

    def _install_confirmation(self) -> None:
        owner = self

        class AcceptedConfirmation(ConfirmationDialog):
            def exec(self) -> int:
                owner._confirmations.append(_widget_text(self))
                self.accept()
                return int(QDialog.DialogCode.Accepted)

        self._monkeypatch.setattr(
            "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
        )

    def _install_add_port_dialog(
        self, zone: str, port: str, protocol: str, target: ApplyTarget
    ) -> None:
        class AcceptedAddPortDialog(AddPortDialog):
            def exec(self) -> int:
                self.zone_combo.setCurrentText(zone)
                self.port_edit.setText(port)
                self.protocol_combo.setCurrentText(protocol.upper())
                _set_combo_data(self.target_combo, target)
                self.accept()
                return int(QDialog.DialogCode.Accepted)

        self._monkeypatch.setattr("app.gui.main_window.AddPortDialog", AcceptedAddPortDialog)

    def _install_add_service_dialog(
        self, zone: str, service_name: str, target: ApplyTarget
    ) -> None:
        class AcceptedAddServiceDialog(AddServiceDialog):
            def exec(self) -> int:
                self.zone_combo.setCurrentText(zone)
                _set_combo_data(self.target_combo, target)
                self.service_combo.setCurrentText(service_name)
                self.accept()
                return int(QDialog.DialogCode.Accepted)

        self._monkeypatch.setattr(
            "app.gui.main_window.AddServiceDialog", AcceptedAddServiceDialog
        )

    def _install_interface_dialog(self, new_zone: str) -> None:
        class AcceptedInterfaceDialog(ChangeInterfaceDialog):
            def exec(self) -> int:
                self.zone_combo.setCurrentText(new_zone)
                self.accept()
                return int(QDialog.DialogCode.Accepted)

        self._monkeypatch.setattr(
            "app.gui.main_window.ChangeInterfaceDialog", AcceptedInterfaceDialog
        )

    def _install_rich_rule_dialog(
        self, zone: str, service_name: str, target: ApplyTarget
    ) -> None:
        class AcceptedRichRuleDialog(RichRuleDialog):
            def exec(self) -> int:
                self.zone_combo.setCurrentText(zone)
                self.service_combo.setCurrentText(service_name)
                self.action_combo.setCurrentText("accept")
                _set_combo_data(self.target_combo, target)
                self.accept()
                return int(QDialog.DialogCode.Accepted)

        self._monkeypatch.setattr(
            "app.gui.main_window.RichRuleDialog", AcceptedRichRuleDialog
        )

    def _install_sudo_dialog(self) -> None:
        owner = self
        password = self._sudo_password
        assert password is not None

        class AcceptedSudoPasswordDialog(SudoPasswordDialog):
            def exec(self) -> int:
                owner._sudo_dialogs.append(self)
                self.password_edit.setText(password)
                self.accept()
                return int(QDialog.DialogCode.Accepted)

        self._monkeypatch.setattr(
            "app.gui.main_window.SudoPasswordDialog", AcceptedSudoPasswordDialog
        )


@pytest.fixture
def application_harness(qtbot, monkeypatch) -> ApplicationHarnessFactory:
    return ApplicationHarnessFactory(qtbot, monkeypatch)


__all__ = [
    "ApplicationHarness",
    "ApplicationHarnessFactory",
    "CredentialSurfaceEvidence",
    "OperationEvidence",
    "application_harness",
]
