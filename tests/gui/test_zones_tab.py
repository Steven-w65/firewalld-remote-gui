from __future__ import annotations

from dataclasses import replace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ServerController
from app.gui.main_window import MainWindow
from app.gui.models.zones_model import ZoneRow, ZonesModel, zone_rows
from app.gui.zones_tab import ZonesTab
from app.models.enums import ApplyTarget
from app.models.firewall import FirewallPort, FirewallSnapshot, RichRule, ZoneState
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def _snapshot(
    *, default_zone: str = "public", stale: bool = False
) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone=default_zone,
        runtime_zones=(
            ZoneState(
                "public",
                interfaces=("eth0",),
                sources=("192.0.2.0/24",),
                services=("ssh", "http"),
                ports=(FirewallPort("8443", "tcp", "public", True, False),),
                protocols=("icmp",),
                masquerade=True,
                forwarding=False,
                rich_rules=(RichRule('rule service name="ssh" accept'),),
            ),
            ZoneState("internal", services=("dns",)),
        ),
        permanent_zones=(
            ZoneState(
                "public",
                interfaces=("ens3",),
                sources=("198.51.100.0/24",),
                services=("ssh",),
                ports=(FirewallPort("443", "tcp", "public", False, True),),
                protocols=("esp",),
                masquerade=False,
                forwarding=True,
                permanent=True,
            ),
            ZoneState("internal", services=("dns", "https"), permanent=True),
        ),
        stale=stale,
    )


def test_zone_rows_preserve_runtime_or_permanent_details() -> None:
    snapshot = _snapshot()

    runtime = next(
        row for row in zone_rows(snapshot, permanent=False) if row.name == "public"
    )
    permanent = next(
        row for row in zone_rows(snapshot, permanent=True) if row.name == "public"
    )

    assert runtime.active
    assert runtime.interfaces == ("eth0",)
    assert runtime.services == ("ssh", "http")
    assert runtime.ports == ("8443/tcp",)
    assert runtime.rich_rule_count == 1
    assert permanent.active
    assert permanent.interfaces == ("ens3",)
    assert permanent.sources == ("198.51.100.0/24",)
    assert permanent.services == ("ssh",)
    assert permanent.ports == ("443/tcp",)
    assert permanent.protocols == ("esp",)
    assert not permanent.masquerade
    assert permanent.forwarding


def test_zones_model_is_read_only_and_exposes_exact_zone_values(qtbot) -> None:
    model = ZonesModel()
    model.set_zones(_snapshot().runtime_zones)

    assert model.rowCount() == 2
    assert model.headerData(0, Qt.Orientation.Horizontal) == "Zone"
    assert model.data(model.index(0, 0)) == "internal"
    assert not (model.flags(model.index(0, 0)) & Qt.ItemFlag.ItemIsEditable)
    assert model.zones() == tuple(
        sorted(_snapshot().runtime_zones, key=lambda zone: zone.name)
    )
    assert isinstance(model.row_at(0), ZoneRow)


def test_zone_tab_switches_runtime_and_permanent_without_mixing(qtbot) -> None:
    snapshot = _snapshot()
    tab = ZonesTab()
    qtbot.addWidget(tab)

    tab.set_snapshot(snapshot)
    tab.table.selectRow(1)
    assert tab.interfaces_value.text() == "eth0"
    assert tab.services_value.text() == "ssh, http"

    tab.view_combo.setCurrentText("Permanent")
    assert tab.model.zones() == tuple(
        sorted(snapshot.permanent_zones, key=lambda zone: zone.name)
    )
    tab.table.selectRow(1)
    assert tab.interfaces_value.text() == "ens3"
    assert tab.services_value.text() == "ssh"
    assert "runtime-derived" in tab.activity_note.text().lower()


def test_zone_tab_empty_and_stale_states_disable_default_change(qtbot) -> None:
    tab = ZonesTab()
    qtbot.addWidget(tab)

    tab.set_snapshot(None)
    assert tab.model.rowCount() == 0
    assert not tab.set_default_button.isEnabled()

    tab.set_snapshot(_snapshot(stale=True))
    tab.default_zone_combo.setCurrentText("internal")
    assert "stale" in tab.status_label.text().lower()
    assert not tab.set_default_button.isEnabled()


@pytest.fixture
def workflow(qtbot):
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    services.next_snapshots["web01"] = _snapshot()
    server = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
    )
    firewall = FirewallController(server)
    server.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    return window, server, firewall, scheduler, services.instances["web01"][0]


def test_default_zone_confirmation_cancel_submits_nothing(
    workflow, monkeypatch
) -> None:
    window, _, _, scheduler, service = workflow

    class CancelledConfirmation:
        def __init__(self, preview, parent):
            assert preview.resource == "public → internal"
            assert preview.target is ApplyTarget.BOTH
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Rejected

        def confirmed(self):
            return False

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", CancelledConfirmation
    )
    window.zones_tab.default_zone_combo.setCurrentText("internal")
    window.zones_tab.set_default_button.click()

    assert service.set_default_zone_calls == []
    assert not any(handle.operation == "set_default_zone" for handle in scheduler.handles)


def test_default_zone_success_refreshes_once_without_reload_and_disables_busy_action(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow

    class AcceptedConfirmation:
        def __init__(self, preview, parent):
            assert preview.resource == "public → internal"
            assert parent is window

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", AcceptedConfirmation
    )
    service.next_snapshot = _snapshot(default_zone="internal")
    window.zones_tab.default_zone_combo.setCurrentText("internal")

    window.zones_tab.set_default_button.click()

    assert server.session_view("web01").busy_operation == "set_default_zone"
    assert not window.zones_tab.set_default_button.isEnabled()
    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert window.zones_tab.current_default_value.text() == "internal"
    assert "verified" in window.zones_tab.result_label.text().lower()
    assert service.set_default_zone_calls == [("internal", ApplyTarget.BOTH, None)]
    assert service.operation_trace[-2:] == ["set_default_zone", "load_snapshot"]
    assert service.reload_calls == []


def test_server_switch_inside_confirmation_invalidates_default_zone_change(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow

    class SwitchingConfirmation:
        def __init__(self, preview, parent):
            del preview, parent

        def exec(self):
            server.select("db01")
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", SwitchingConfirmation
    )
    window.zones_tab.default_zone_combo.setCurrentText("internal")

    window.zones_tab.set_default_button.click()

    assert window.current_server_id == "db01"
    assert service.set_default_zone_calls == []
    assert not any(
        handle.operation == "set_default_zone" and not handle.has_run
        for handle in scheduler.handles
    )


def test_late_default_zone_result_never_replaces_selected_other_server(
    workflow, monkeypatch
) -> None:
    window, server, _, scheduler, service = workflow

    class SwitchingConfirmation:
        def __init__(self, preview, parent):
            del preview, parent

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr(
        "app.gui.main_window.ConfirmationDialog", SwitchingConfirmation
    )
    service.next_snapshot = _snapshot(default_zone="internal")
    window.zones_tab.default_zone_combo.setCurrentText("internal")
    window.zones_tab.set_default_button.click()
    server.select("db01")

    scheduler.pending("web01", "set_default_zone").run_synchronously_for_test()

    assert window.current_server_id == "db01"
    assert window.zones_tab.current_default_value.text() == "—"
    server.select("web01")
    assert window.zones_tab.current_default_value.text() == "internal"
