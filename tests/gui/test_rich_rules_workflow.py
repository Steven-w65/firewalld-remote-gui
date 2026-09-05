from __future__ import annotations

from dataclasses import FrozenInstanceError
from threading import Event

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QDialog

from app.controllers.firewall_controller import FirewallController
from app.controllers.server_controller import ControllerOperationError, ServerController
from app.gui.dialogs.rich_rule_dialog import RichRuleDialog
from app.gui.main_window import MainWindow
from app.gui.models.rich_rules_model import merge_rich_rule_rows
from app.gui.rich_rules_tab import RichRulesTab
from app.models.command import CommandResult, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget
from app.models.firewall import FirewallSnapshot, RichRule, ZoneState
from app.models.rich_rule import RichRuleRequest, RichRuleRow
from app.models.enums import ConnectionStatus, TargetStatus
from app.utils.errors import (
    FirewallCommandError,
    PostMutationVerificationError,
    SudoAuthenticationRequiredError,
)
from app.workers.scheduler import OperationScheduler
from tests.controllers.fakes import (
    FakeConfigManager,
    ManagerFactory,
    ManualScheduler,
    ServiceFactory,
    make_loaded,
)


def _rule(
    *,
    source: str | None = None,
    destination: str | None = None,
    service: str | None = "ssh",
    port: str | None = None,
    protocol: str | None = None,
    action: str = "accept",
) -> RichRule:
    family = None
    if source is not None or destination is not None:
        family = "ipv6" if ":" in (source or destination or "") else "ipv4"
    clauses = ["rule"]
    if family:
        clauses.append(f'family="{family}"')
    if source:
        clauses.append(f'source address="{source}"')
    if destination:
        clauses.append(f'destination address="{destination}"')
    if service:
        clauses.append(f'service name="{service}"')
    else:
        clauses.append(f'port port="{port}" protocol="{protocol}"')
    clauses.append(action)
    return RichRule(
        " ".join(clauses),
        source=source,
        destination=destination,
        service=service,
        port=port,
        protocol=protocol,
        action=action,
        family=family,
    )


def _snapshot(
    runtime: tuple[RichRule, ...], permanent: tuple[RichRule, ...]
) -> FirewallSnapshot:
    return FirewallSnapshot(
        hostname="web01",
        distribution="Test Linux",
        firewalld_running=True,
        firewalld_version="2.1.0",
        default_zone="public",
        runtime_zones=(ZoneState("public", rich_rules=runtime),),
        permanent_zones=(
            ZoneState("public", rich_rules=permanent, permanent=True),
        ),
        available_services=("http", "ssh"),
    )


def test_rule_requires_exactly_one_service_or_port(qtbot) -> None:
    dialog = RichRuleDialog(("public",), ("ssh", "http"), "public")
    qtbot.addWidget(dialog)

    dialog.service_combo.setCurrentText("ssh")
    dialog.port_edit.setText("22")

    assert not dialog.add_button.isEnabled()


def test_rule_dialog_rejects_shell_shaped_and_mixed_family_addresses(qtbot) -> None:
    dialog = RichRuleDialog(("public",), ("ssh",), "public")
    qtbot.addWidget(dialog)
    dialog.service_combo.setCurrentText("ssh")

    dialog.source_edit.setText("192.0.2.1; id")
    assert not dialog.add_button.isEnabled()

    dialog.source_edit.setText("192.0.2.0/24")
    dialog.destination_edit.setText("2001:db8::/64")
    assert not dialog.add_button.isEnabled()


def test_rule_dialog_has_no_free_form_editor_and_cancel_is_default(qtbot) -> None:
    dialog = RichRuleDialog(("public",), ("ssh",), "public")
    qtbot.addWidget(dialog)

    assert not hasattr(dialog, "advanced_rule_edit")
    assert dialog.defaultButton() is dialog.cancel_button


def test_dialog_returns_immutable_normalized_structured_request(qtbot) -> None:
    dialog = RichRuleDialog(("public",), ("ssh",), "public")
    qtbot.addWidget(dialog)
    dialog.source_edit.setText("192.0.2.4/24")
    dialog.service_combo.setCurrentText("ssh")
    dialog.accept()

    request = dialog.request()
    assert request == RichRuleRequest(
        "public",
        "192.0.2.0/24",
        None,
        "ssh",
        None,
        None,
        "accept",
        ApplyTarget.BOTH,
    )
    with pytest.raises(FrozenInstanceError):
        request.action = "drop"


def test_port_request_requires_protocol_and_strict_port() -> None:
    with pytest.raises(ValueError):
        RichRuleRequest(
            "public", None, None, None, "22", None, "accept", ApplyTarget.RUNTIME
        )
    with pytest.raises(ValueError):
        RichRuleRequest(
            "public",
            None,
            None,
            None,
            "22;id",
            "tcp",
            "accept",
            ApplyTarget.RUNTIME,
        )


def test_rich_rule_rows_merge_exact_structured_identity_not_summary() -> None:
    common = _rule(source="192.0.2.0/24")
    other_source = _rule(source="198.51.100.0/24")
    rows = merge_rich_rule_rows(_snapshot((common, other_source), (common,)), "public")

    assert len(rows) == 2
    assert rows[0].rule != rows[1].rule
    assert sum(row.runtime and row.permanent for row in rows) == 1
    assert all("ssh" in row.summary for row in rows)


def test_unsupported_raw_rules_are_display_only_and_merge_only_by_exact_text() -> None:
    first = RichRule('rule family="ipv4" source address="192.0.2.0/24" log accept')
    second = RichRule('rule family="ipv4" source address="192.0.2.0/24" limit value="1/m" accept')
    rows = merge_rich_rule_rows(_snapshot((first, second), (first,)), "public")

    assert len(rows) == 2
    merged = next(row for row in rows if row.rule is first)
    assert merged.runtime and merged.permanent
    assert all(not row.supported for row in rows)


def test_parser_visible_unsupported_protocol_rule_remains_display_only() -> None:
    protocol_only = RichRule(
        'rule family="ipv4" protocol value="icmp" accept',
        protocol="icmp",
        action="accept",
        family="ipv4",
    )

    (row,) = merge_rich_rule_rows(_snapshot((protocol_only,), ()), "public")

    assert row.rule is protocol_only
    assert not row.supported


def test_row_retains_exact_snapshot_rule_and_is_immutable() -> None:
    exact = _rule(destination="203.0.113.0/24", service="http")
    (row,) = merge_rich_rule_rows(_snapshot((exact,), ()), "public")

    assert isinstance(row, RichRuleRow)
    assert row.rule is exact
    with pytest.raises(FrozenInstanceError):
        row.rule = _rule()


@pytest.fixture
def workflow(qtbot):
    del qtbot
    scheduler = ManualScheduler()
    managers = ManagerFactory()
    services = ServiceFactory()
    ssh = _rule()
    services.next_snapshots["web01"] = _snapshot((ssh,), (ssh,))
    server = ServerController(
        FakeConfigManager(make_loaded("web01", "db01")),
        scheduler,
        managers,
        services,
    )
    firewall = FirewallController(server)
    server.connect("web01")
    scheduler.pending("web01", "connect").run_synchronously_for_test()
    return server, firewall, scheduler, services.instances["web01"][0]


def test_preview_add_is_pure_inventory_bound_and_target_aware(workflow) -> None:
    _server, firewall, _scheduler, service = workflow
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.BOTH
    )

    first = firewall.preview_add_rich_rule("web01", request)
    second = firewall.preview_add_rich_rule("web01", request)

    assert first == second
    assert first.operation == "Add Structured Rich Rule"
    assert first.resource == "Accept http"
    assert service.add_rich_rule_calls == []
    with pytest.raises(ValueError):
        firewall.preview_add_rich_rule(
            "web01",
            RichRuleRequest(
                "missing",
                None,
                None,
                "http",
                None,
                None,
                "accept",
                ApplyTarget.RUNTIME,
            ),
        )
    with pytest.raises(ValueError):
        firewall.preview_add_rich_rule(
            "web01",
            RichRuleRequest(
                "public",
                None,
                None,
                "invented",
                None,
                None,
                "accept",
                ApplyTarget.RUNTIME,
            ),
        )


def test_preview_add_rejects_fully_present_but_allows_partial_both(workflow) -> None:
    _server, firewall, _scheduler, _service = workflow
    ssh = RichRuleRequest(
        "public", None, None, "ssh", None, None, "accept", ApplyTarget.BOTH
    )
    with pytest.raises(ValueError):
        firewall.preview_add_rich_rule("web01", ssh)

    snapshot = _snapshot((_rule(service="http"),), ())
    _server._sessions["web01"].snapshot = snapshot
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.BOTH
    )
    assert firewall.preview_add_rich_rule("web01", request).target is ApplyTarget.BOTH


def test_remove_requires_supported_exact_row_and_reports_ssh_risk(workflow) -> None:
    _server, firewall, _scheduler, _service = workflow
    row = RichRuleRow("public", "Accept ssh", True, True, _rule())

    preview = firewall.preview_remove_rich_rule("web01", row, ApplyTarget.BOTH)

    assert preview.risk.is_high
    assert "management port 22" in " ".join(preview.risk.reasons)
    with pytest.raises(ValueError):
        firewall.preview_remove_rich_rule(
            "web01",
            RichRuleRow(
                "public", "Display", True, False, RichRule("rule log accept")
            ),
            ApplyTarget.RUNTIME,
        )
    with pytest.raises(ValueError):
        firewall.preview_remove_rich_rule(
            "web01", RichRuleRow("public", "Accept ssh", True, False, _rule()), ApplyTarget.BOTH
        )


def test_partial_both_add_reconciles_only_missing_target_and_refreshes_once(
    workflow,
) -> None:
    server, firewall, scheduler, service = workflow
    runtime_rule = _rule(service="http")
    server._sessions["web01"].snapshot = _snapshot((runtime_rule,), ())
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.BOTH
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    service.next_snapshot = _snapshot((runtime_rule,), (runtime_rule,))
    events: list[str] = []
    firewall.snapshot_changed.connect(lambda *_args: events.append("snapshot"))
    firewall.operation_result.connect(lambda *_args: events.append("result"))

    firewall.apply_add_rich_rule("web01", preview, request)
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert service.add_rich_rule_calls == [
        (
            "public",
            None,
            None,
            "http",
            None,
            None,
            "accept",
            ApplyTarget.PERMANENT,
            None,
        )
    ]
    assert service.operation_trace[-2:] == ["add_rich_rule", "load_snapshot"]
    assert events == ["snapshot", "result"]
    assert service.reload_calls == []


def test_remove_passes_exact_snapshot_structured_fields_and_never_raw_text(
    workflow,
) -> None:
    _server, firewall, scheduler, service = workflow
    exact = _rule(
        source="192.0.2.0/24", destination="203.0.113.0/24", service="http"
    )
    _server._sessions["web01"].snapshot = _snapshot((exact,), ())
    row = merge_rich_rule_rows(_server.session_view("web01").snapshot, "public")[0]
    preview = firewall.preview_remove_rich_rule("web01", row, ApplyTarget.RUNTIME)
    service.next_snapshot = _snapshot((), ())

    firewall.apply_remove_rich_rule("web01", preview, row, ApplyTarget.RUNTIME)
    scheduler.pending("web01", "remove_rich_rule").run_synchronously_for_test()

    assert service.remove_rich_rule_calls == [
        (
            "public",
            "192.0.2.0/24",
            "203.0.113.0/24",
            "http",
            None,
            None,
            "accept",
            ApplyTarget.RUNTIME,
            None,
        )
    ]
    assert exact.rule not in repr(service.remove_rich_rule_calls)


def test_apply_revalidates_complete_preview_and_current_rule_membership(workflow) -> None:
    server, firewall, _scheduler, _service = workflow
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    server.select("db01")
    with pytest.raises(RuntimeError, match="selected"):
        firewall.apply_add_rich_rule("web01", preview, request)

    server.select("web01")
    server._sessions["web01"].snapshot = _snapshot((_rule(service="http"),), ())
    with pytest.raises(RuntimeError, match="changed"):
        firewall.apply_add_rich_rule("web01", preview, request)


def test_tab_displays_raw_rules_but_never_enables_remove_for_them(qtbot) -> None:
    tab = RichRulesTab()
    qtbot.addWidget(tab)
    raw = RichRule("rule log prefix=unsafe accept")
    snapshot = _snapshot((raw,), ())
    from app.controllers.session import ServerSessionView

    view = ServerSessionView(
        server_id="web01",
        name="WEB01",
        host="web01.example.test",
        port=22,
        username="operator",
        sudo_enabled=True,
        status=ConnectionStatus.CONNECTED,
        snapshot=snapshot,
        latest_error=None,
        busy_operation=None,
        generation=0,
    )
    tab.set_session(view)
    tab.table.selectRow(0)

    assert tab.rows()[0].rule is raw
    assert "display only" in tab.model.data(tab.model.index(0, 4)).lower()
    assert not tab.remove_button.isEnabled()


def _confirm(monkeypatch, captured: list[object] | None = None) -> None:
    class AcceptedConfirmation:
        def __init__(self, preview, parent=None):
            if captured is not None:
                captured.append(preview)
            assert parent is not None

        def exec(self):
            return QDialog.DialogCode.Accepted

        def confirmed(self):
            return True

    monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", AcceptedConfirmation)


def _accept_add(monkeypatch, target: ApplyTarget = ApplyTarget.BOTH) -> None:
    class AcceptedRuleDialog:
        def __init__(self, zones, services, current_zone, parent=None):
            assert zones == ("public",)
            assert services == ("http", "ssh")
            assert current_zone == "public"
            assert parent is not None

        def exec(self):
            return QDialog.DialogCode.Accepted

        def request(self):
            return RichRuleRequest(
                "public", None, None, "http", None, None, "accept", target
            )

    monkeypatch.setattr("app.gui.main_window.RichRuleDialog", AcceptedRuleDialog)


def test_main_window_replaces_only_rich_rules_placeholder_and_adds_verified_row(
    workflow, qtbot, monkeypatch
) -> None:
    server, firewall, scheduler, service = workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    _accept_add(monkeypatch)
    _confirm(monkeypatch)
    http = _rule(service="http")
    service.next_snapshot = _snapshot((_rule(), http), (_rule(), http))

    assert window.tabs.widget(5) is window.rich_rules_tab
    window.rich_rules_tab.add_button.click()
    assert server.session_view("web01").busy_operation == "add_rich_rule"
    assert not window.rich_rules_tab.add_button.isEnabled()
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert any(row.rule.service == "http" for row in window.rich_rules_tab.rows())
    assert "completed" in window.rich_rules_tab.result_label.text().lower()
    assert service.reload_calls == []


def test_remove_selected_rule_derives_target_and_uses_high_risk_confirmation(
    workflow, qtbot, monkeypatch
) -> None:
    server, firewall, scheduler, service = workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    previews: list[object] = []
    _confirm(monkeypatch, previews)
    service.next_snapshot = _snapshot((), ())
    window.rich_rules_tab.table.selectRow(0)

    window.rich_rules_tab.remove_button.click()

    assert previews[0].target is ApplyTarget.BOTH
    assert previews[0].risk.is_high
    scheduler.pending("web01", "remove_rich_rule").run_synchronously_for_test()
    assert window.rich_rules_tab.rows() == ()


@pytest.mark.parametrize("cancel_stage", ("add", "confirmation"))
def test_cancelled_rule_dialogs_submit_no_write(
    workflow, qtbot, monkeypatch, cancel_stage
) -> None:
    server, firewall, scheduler, service = workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)

    class Cancelled:
        def __init__(self, *_args, **_kwargs):
            pass

        def exec(self):
            return QDialog.DialogCode.Rejected

        def request(self):
            return None

        def confirmed(self):
            return False

    if cancel_stage == "add":
        monkeypatch.setattr("app.gui.main_window.RichRuleDialog", Cancelled)
    else:
        _accept_add(monkeypatch)
        monkeypatch.setattr("app.gui.main_window.ConfirmationDialog", Cancelled)

    window.rich_rules_tab.add_button.click()

    assert service.add_rich_rule_calls == []
    assert not any(handle.operation == "add_rich_rule" for handle in scheduler.handles)


def test_late_rule_result_cannot_overwrite_other_selected_server(
    workflow, qtbot, monkeypatch
) -> None:
    server, firewall, scheduler, service = workflow
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    _accept_add(monkeypatch, ApplyTarget.RUNTIME)
    _confirm(monkeypatch)
    service.next_snapshot = _snapshot((_rule(), _rule(service="http")), (_rule(),))

    window.rich_rules_tab.add_button.click()
    server.select("db01")
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert window.current_server_id == "db01"
    assert window.rich_rules_tab.rows() == ()
    server.select("web01")
    assert any(row.rule.service == "http" for row in window.rich_rules_tab.rows())


def test_old_internal_handle_cannot_complete_later_rich_rule_intent(workflow) -> None:
    _server, firewall, scheduler, service = workflow
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    firewall.apply_add_rich_rule("web01", preview, request)
    old_internal = firewall._pending[("web01", 0, "add_rich_rule")].internal
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    current_preview = firewall.preview_add_rich_rule("web01", request)
    current = firewall.apply_add_rich_rule("web01", current_preview, request)
    published: list[object] = []
    finished: list[str] = []
    firewall.operation_result.connect(lambda _sid, result: published.append(result))
    current.finished.connect(lambda *_args: finished.append(_args[-1]))
    old_internal.succeeded.emit(
        "web01", 0, "add_rich_rule", CompositeOperationResult("add_rich_rule")
    )
    old_internal.finished.emit("web01", 0, "add_rich_rule")
    assert published == finished == []

    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()
    assert len(published) == 1
    assert finished == ["add_rich_rule"]
    assert len(service.add_rich_rule_calls) == 2


def test_old_generation_rich_rule_completion_never_publishes(workflow) -> None:
    server, firewall, scheduler, service = workflow
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    handle = firewall.apply_add_rich_rule("web01", preview, request)
    outcomes: list[object] = []
    handle.succeeded.connect(lambda *_args: outcomes.append(_args[-1]))

    server.disconnect("web01")
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert outcomes == []
    assert server.session_view("web01").status is ConnectionStatus.DISCONNECTED
    assert server.session_view("web01").snapshot is None
    assert len(service.add_rich_rule_calls) == 1


def test_real_scheduler_keeps_gui_responsive_while_rich_rule_write_is_blocked(
    qtbot, monkeypatch
) -> None:
    scheduler = OperationScheduler(max_threads=2)
    managers = ManagerFactory()
    services = ServiceFactory()
    services.next_snapshots["web01"] = _snapshot((_rule(),), (_rule(),))
    server = ServerController(
        FakeConfigManager(make_loaded("web01")), scheduler, managers, services
    )
    firewall = FirewallController(server)
    server.connect("web01")
    qtbot.waitUntil(
        lambda: server.session_view("web01").status is ConnectionStatus.CONNECTED,
        timeout=3000,
    )
    service = services.instances["web01"][0]
    http = _rule(service="http")
    service.next_snapshot = _snapshot((_rule(), http), (_rule(),))
    entered, release, gui_tick = Event(), Event(), Event()
    service.add_rich_rule_entered = entered
    service.add_rich_rule_release = release
    window = MainWindow(server, firewall)
    qtbot.addWidget(window)
    _accept_add(monkeypatch, ApplyTarget.RUNTIME)
    _confirm(monkeypatch)

    window.rich_rules_tab.add_button.click()
    assert entered.wait(2)
    QTimer.singleShot(0, gui_tick.set)

    qtbot.waitUntil(gui_tick.is_set, timeout=500)
    assert not window.rich_rules_tab.add_button.isEnabled()
    release.set()
    qtbot.waitUntil(
        lambda: any(row.rule.service == "http" for row in window.rich_rules_tab.rows()),
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)


def _target_result(
    target: ApplyTarget,
    execution: TargetStatus,
    verification: TargetStatus,
    *,
    authentication_failed: bool = False,
) -> TargetResult:
    return TargetResult(
        target,
        execution,
        verification,
        CommandResult(
            False,
            1,
            "stdout-secret",
            "stderr-password",
            "web01",
            "rich-rule-secret",
            0.1,
        ),
        "unsafe-secret backend detail",
        authentication_failed=authentication_failed,
    )


def test_partial_raw_result_is_sanitized_after_one_refresh(workflow) -> None:
    _server, firewall, scheduler, service = workflow
    service.next_add_rich_rule_result = CompositeOperationResult(
        "add_rich_rule",
        permanent=_target_result(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
        ),
        runtime=_target_result(
            ApplyTarget.RUNTIME, TargetStatus.FAILED, TargetStatus.NOT_RUN
        ),
    )
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.BOTH
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    published: list[CompositeOperationResult] = []
    firewall.operation_result.connect(lambda _sid, result: published.append(result))

    firewall.apply_add_rich_rule("web01", preview, request)
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert len(published) == 1 and published[0].is_partial
    assert published[0].permanent.result is None
    assert "secret" not in repr(published[0])
    assert service.load_calls == [None, None]


def test_refresh_failure_marks_snapshot_stale_and_publishes_safe_rule_error(
    workflow,
) -> None:
    server, firewall, scheduler, service = workflow
    service.next_load_error = FirewallCommandError("web01", "unsafe-secret")
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    errors: list[ControllerOperationError] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))

    firewall.apply_add_rich_rule("web01", preview, request)
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert server.session_view("web01").snapshot.stale
    assert errors[-1].category == "post_mutation_refresh"
    assert "rich-rule change" in errors[-1].message.lower()
    assert "secret" not in repr(errors[-1])
    assert len(service.add_rich_rule_calls) == 1


def test_pre_mutation_sudo_retry_uses_one_public_rule_facade(workflow) -> None:
    server, firewall, scheduler, service = workflow
    service.next_add_rich_rule_error = SudoAuthenticationRequiredError(
        "web01", "add_rich_rule"
    )
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))

    handle = firewall.apply_add_rich_rule("web01", preview, request)
    succeeded: list[object] = []
    finished: list[str] = []
    handle.succeeded.connect(lambda *_args: succeeded.append(_args[-1]))
    handle.finished.connect(lambda *_args: finished.append(_args[-1]))
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()
    assert len(requests) == 1 and succeeded == finished == []

    assert server.resolve_sudo_password(requests[0], "sudo-one-use-secret")
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert [call[-1] for call in service.add_rich_rule_calls] == [
        None,
        "sudo-one-use-secret",
    ]
    assert len(succeeded) == 1
    assert finished == ["add_rich_rule"]
    assert "secret" not in repr(handle)


def test_post_mutation_auth_partial_never_prompts_or_reissues_rule(workflow) -> None:
    server, firewall, scheduler, service = workflow
    generation = server.session_view("web01").generation
    assert server.provide_sudo_password("web01", generation, "sudo-secret")
    service.next_remove_rich_rule_result = CompositeOperationResult(
        "remove_rich_rule",
        permanent=_target_result(
            ApplyTarget.PERMANENT,
            TargetStatus.SUCCEEDED,
            TargetStatus.SUCCEEDED,
        ),
        runtime=_target_result(
            ApplyTarget.RUNTIME,
            TargetStatus.FAILED,
            TargetStatus.NOT_RUN,
            authentication_failed=True,
        ),
    )
    requests: list[object] = []
    server.sudo_password_required.connect(lambda _sid, value: requests.append(value))
    row = RichRuleRow("public", "Accept ssh", True, True, _rule())
    preview = firewall.preview_remove_rich_rule("web01", row, ApplyTarget.BOTH)

    firewall.apply_remove_rich_rule("web01", preview, row, ApplyTarget.BOTH)
    scheduler.pending("web01", "remove_rich_rule").run_synchronously_for_test()

    assert requests == []
    assert len(service.remove_rich_rule_calls) == 1
    assert service.remove_rich_rule_calls[0][-1] == "sudo-secret"
    assert server._sessions["web01"].sudo_password is None


def test_post_mutation_verification_error_is_rule_specific_and_not_retried(
    workflow,
) -> None:
    _server, firewall, scheduler, service = workflow
    service.next_add_rich_rule_error = PostMutationVerificationError(
        "web01", "add_rich_rule"
    )
    request = RichRuleRequest(
        "public", None, None, "http", None, None, "accept", ApplyTarget.RUNTIME
    )
    preview = firewall.preview_add_rich_rule("web01", request)
    errors: list[ControllerOperationError] = []
    firewall.error_raised.connect(lambda _sid, error: errors.append(error))

    firewall.apply_add_rich_rule("web01", preview, request)
    scheduler.pending("web01", "add_rich_rule").run_synchronously_for_test()

    assert len(service.add_rich_rule_calls) == 1
    assert errors[-1].category == "post_mutation_verification"
    assert "rich-rule change" in errors[-1].message.lower()
    assert "reloaded" not in errors[-1].message.lower()
