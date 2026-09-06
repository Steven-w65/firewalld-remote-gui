from __future__ import annotations

from app.models.enums import ApplyTarget
from tests.acceptance.harness import application_harness


def test_three_server_port_lifecycle_remains_isolated(qtbot, application_harness):
    del qtbot
    app = application_harness.with_servers("web01", "db01", "test01")
    assert app.server_ids() == ("web01", "db01", "test01")

    cycles = (
        ("web01", "8080", "tcp", ApplyTarget.BOTH, True, True),
        ("db01", "5432", "tcp", ApplyTarget.RUNTIME, True, False),
        ("test01", "5353", "udp", ApplyTarget.PERMANENT, False, True),
    )
    for server_id, port, protocol, target, runtime, permanent in cycles:
        app.select(server_id)
        assert app.selected_server_id() == server_id
        app.connect(server_id)
        app.add_port(server_id, "public", port, protocol, target)
        app.refresh(server_id)
        row = app.port_row(server_id, port, protocol)
        assert row is not None
        assert (row.runtime, row.permanent) == (runtime, permanent)

    for owner, port, protocol, _target, _runtime, _permanent in cycles:
        for selected, *_rest in cycles:
            app.select(selected)
            assert app.selected_server_id() == selected
            assert (app.port_row(selected, port, protocol) is not None) is (
                selected == owner
            )

    app.select("web01")
    app.add_port("web01", "public", "8443", "tcp", ApplyTarget.BOTH)
    add_evidence = app.last_operation_evidence()
    assert add_evidence is not None
    assert (
        add_evidence.mutation_calls,
        add_evidence.snapshot_refreshes,
        add_evidence.confirmations,
    ) == (1, 1, 1)
    assert app.port_row("web01", "8443", "tcp").runtime
    assert app.port_row("web01", "8443", "tcp").permanent

    app.remove_port("web01", "public", "8443", "tcp", ApplyTarget.BOTH)
    remove_evidence = app.last_operation_evidence()
    assert remove_evidence is not None
    assert (
        remove_evidence.mutation_calls,
        remove_evidence.snapshot_refreshes,
        remove_evidence.confirmations,
    ) == (1, 1, 1)
    assert app.port_row("web01", "8443", "tcp") is None


def test_readable_ssh_failure_is_displayed_without_crashing(application_harness):
    app = application_harness.with_servers("web01")
    app.fail_next_ssh_authentication("web01")
    assert "SSH Authentication Failed" in app.error_text()
    assert "rejected the configured SSH credentials" in app.error_text()


def test_partial_runtime_and_permanent_result_is_visible(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    app.add_port(
        "web01", "public", "8443", "tcp", ApplyTarget.BOTH, partial=True
    )
    row = app.port_row("web01", "8443", "tcp")
    assert row is not None and not row.runtime and row.permanent
    assert "partially completed" in app.visible_text()


def test_service_add_and_remove_use_verified_rendered_state(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    app.add_service("web01", "public", "https", ApplyTarget.BOTH)
    row = app.service_row("web01", "https")
    assert row is not None and row.runtime and row.permanent
    app.remove_service("web01", "public", "https", ApplyTarget.BOTH)
    assert app.service_row("web01", "https") is None


def test_zone_display_and_default_zone_change_are_confirmed(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    assert app.zone_names("web01") == ("internal", "public")
    app.set_default_zone("web01", "internal")
    confirmation = app.confirmation_text()
    assert "public → internal" in confirmation
    assert "Runtime + Permanent" in confirmation
    assert "internal" in app.visible_text()


def test_active_interface_move_warns_with_management_port(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    app.change_interface("web01", "eth0", "internal")
    row = app.interface_row("web01", "eth0")
    assert row is not None and row.runtime_zone == row.permanent_zone == "internal"
    warning = app.confirmation_text().lower()
    assert "management port 22" in warning
    assert "apply anyway" in warning


def test_structured_rich_rule_add_and_remove_has_no_raw_editor(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    app.add_rich_rule("web01", "public", "http", ApplyTarget.BOTH)
    row = app.rich_rule_row("web01", "http")
    assert row is not None and row.supported and row.runtime and row.permanent
    assert all("raw" not in value.lower() for value in app.editable_field_descriptors())
    app.remove_rich_rule("web01", "public", "http", ApplyTarget.BOTH)
    assert app.rich_rule_row("web01", "http") is None


def test_reload_requires_runtime_loss_warning_and_renders_outcome(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    app.reload("web01")
    assert "runtime-only changes may disappear" in app.confirmation_text().lower()
    assert "reload completed and verified" in app.visible_text().lower()


def test_management_port_removal_requires_apply_anyway(application_harness):
    app = application_harness.with_servers("web01")
    app.connect("web01")
    app.remove_port("web01", "public", "22", "tcp", ApplyTarget.BOTH)
    warning = app.confirmation_text().lower()
    assert "tcp port 22" in warning
    assert "apply anyway" in warning
