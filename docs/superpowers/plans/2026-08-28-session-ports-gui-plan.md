# Session Core and Ports GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the tested backend to a responsive multi-server PySide6 shell and deliver the complete table-based Ports workflow.

**Architecture:** A keyed `QThreadPool` scheduler serializes work within a server and publishes typed outcomes through Qt signals. Controllers own isolated `ServerSession` values, while GUI widgets render snapshots and emit intentions without invoking SSH or constructing commands.

**Tech Stack:** Python 3.11+, PySide6, Paramiko backend from Plan 2, pytest, pytest-qt

**Spec:** `docs/superpowers/specs/2026-08-28-remote-firewalld-manager-design.md`

## Global Constraints

- Complete both earlier plans and retain their public interfaces.
- Never run SSH or firewalld work on the Qt GUI thread.
- Serialize operations by server ID and permit different servers to run concurrently.
- Discard results whose session generation no longer matches.
- Update Qt widgets only on the GUI thread.
- Do not connect servers automatically at startup.
- Use `QTableView` and a proper model for Ports.
- Validate, assess risk, preview, confirm, execute, refresh, and verify every write.
- Keep passwords out of widget state immediately after submission and out of logs permanently.

---

## File Map

- `app/workers/scheduler.py`: keyed job queue on `QThreadPool`.
- `app/controllers/session.py`: isolated mutable session owner around immutable snapshots.
- `app/controllers/server_controller.py`: configuration/session lifecycle and connection orchestration.
- `app/controllers/firewall_controller.py`: validated read/write intentions and confirmations.
- `app/gui/main_window.py`: application shell and selected-server routing.
- `app/gui/server_sidebar.py`: server list and connection states.
- `app/gui/overview_tab.py`: connection summary and connection test.
- `app/gui/ports_tab.py`: filters, table, and port actions.
- `app/gui/models/ports_model.py`: `QAbstractTableModel` for merged runtime/permanent rows.
- `app/gui/dialogs/host_key_dialog.py`: explicit unknown-host trust.
- `app/gui/dialogs/sudo_password_dialog.py`: masked memory-only credential input.
- `app/gui/dialogs/confirmation_dialog.py`: normal and high-risk previews.
- `app/gui/dialogs/add_port_dialog.py`: validated port request.

### Task 1: Keyed Qt operation scheduler

**Files:**
- Create: `app/workers/__init__.py`
- Create: `app/workers/scheduler.py`
- Create: `tests/workers/test_scheduler.py`

**Interfaces:**
- Produces: `OperationScheduler.submit(server_id: str, generation: int, operation: str, work: Callable[[], T]) -> JobHandle[T]`
- `JobHandle` signals: `started(server_id, generation, operation)`, `succeeded(server_id, generation, operation, value)`, `failed(server_id, generation, operation, error)`, `finished(server_id, generation, operation)`
- Produces: `OperationScheduler.cancel_pending(server_id: str) -> None`
- Produces: `OperationScheduler.is_busy(server_id: str) -> bool`

- [ ] **Step 1: Write failing scheduler tests**

```python
from threading import Event, Lock

from app.workers.scheduler import OperationScheduler


def test_jobs_for_same_server_never_overlap(qtbot):
    scheduler = OperationScheduler(max_threads=4)
    first_started, release_first, second_started = Event(), Event(), Event()

    def first():
        first_started.set()
        release_first.wait(2)

    def second():
        second_started.set()

    scheduler.submit("web01", 1, "first", first)
    scheduler.submit("web01", 1, "second", second)
    assert first_started.wait(1)
    assert not second_started.wait(0.1)
    release_first.set()
    assert second_started.wait(1)


def test_jobs_for_different_servers_can_overlap(qtbot):
    scheduler = OperationScheduler(max_threads=4)
    reached = {"a": Event(), "b": Event()}
    release = Event()
    scheduler.submit("a", 1, "read", lambda: (reached["a"].set(), release.wait(2)))
    scheduler.submit("b", 1, "read", lambda: (reached["b"].set(), release.wait(2)))
    assert reached["a"].wait(1) and reached["b"].wait(1)
    release.set()
```

Add signal-thread tests using `qtbot.waitSignal` to prove results arrive on the QObject receiver's thread and pending cancellation does not interrupt a running command.

- [ ] **Step 2: Run scheduler tests and confirm failure**

Run: `python -m pytest tests/workers/test_scheduler.py -v`

Expected: FAIL because the worker package is missing.

- [ ] **Step 3: Implement per-key FIFO queues on one QThreadPool**

Maintain a locked deque per server and schedule only its head. The runnable catches `Exception` and emits it as data; after finish, the scheduler removes the head and launches the next item. Never swallow `BaseException`. Mark busy from enqueue until the final queued job finishes.

- [ ] **Step 4: Run scheduler tests repeatedly**

Run: `1..5 | ForEach-Object { python -m pytest tests/workers/test_scheduler.py -v; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE } }`

Expected: all five runs PASS without hangs.

- [ ] **Step 5: Commit scheduling**

```bash
git add app/workers tests/workers/test_scheduler.py
git commit -m "feat: serialize background work per server"
```

### Task 2: Isolated server sessions and configuration reload

**Files:**
- Create: `app/controllers/__init__.py`
- Create: `app/controllers/session.py`
- Create: `app/controllers/server_controller.py`
- Create: `tests/controllers/fakes.py`
- Create: `tests/controllers/test_server_controller.py`

**Interfaces:**
- Produces: `ServerSession(config, generation, status, snapshot, latest_error, sudo_password, busy_operation)`
- Produces: `ServerController.sessions() -> tuple[ServerSessionView, ...]`
- Produces: `ServerController.session_view(server_id: str) -> ServerSessionView`
- Produces: `ServerController.select(server_id: str) -> None`
- Produces: `ServerController.connect(server_id: str) -> JobHandle`
- Produces: `disconnect`, `reconnect`, `refresh`, `test_connection`, and `reload_configuration`
- Controller signals: `sessions_changed`, `selection_changed(server_id)`, `session_changed(server_id)`, `host_key_required(server_id, challenge)`, `sudo_password_required(server_id, request)`, `error_raised(server_id, error)`

- [ ] **Step 1: Write failing isolation and stale-result tests**

```python
def test_each_server_owns_a_distinct_ssh_manager(controller, manager_factory):
    controller.connect("web01")
    controller.connect("db01")
    manager_factory.finish_all()
    assert manager_factory.instances["web01"] is not manager_factory.instances["db01"]


def test_result_from_old_generation_is_discarded(controller, scheduler):
    controller.connect("web01")
    old_job = scheduler.pending("web01")
    controller.disconnect("web01")
    old_job.succeed(make_snapshot(default_zone="public"))
    assert controller.session_view("web01").snapshot is None


def test_invalid_reload_preserves_current_sessions(controller, config_manager):
    before = controller.sessions()
    config_manager.next_load_error = ConfigurationError("invalid YAML")
    controller.reload_configuration()
    assert controller.sessions() == before
```

Add changed/removed/new profile reload cases, independent cached snapshots, cached sudo password clearing, and no startup connection.

- [ ] **Step 2: Run controller tests and confirm failure**

Run: `python -m pytest tests/controllers/test_server_controller.py -v`

Expected: FAIL because controller types are missing.

- [ ] **Step 3: Implement session ownership and controller state transitions**

Keep mutable connection resources private inside `ServerSession`; expose frozen `ServerSessionView` copies to widgets. Increment generation before disconnect/replacement. Connection success triggers `FirewalldService.load_snapshot`; connection failure changes only the matching session. Never log `ServerConfig` representations.

- [ ] **Step 4: Run controller tests**

Run: `python -m pytest tests/controllers/test_server_controller.py -v`

Expected: PASS for isolation, reload, stale results, and state transitions.

- [ ] **Step 5: Commit session control**

```bash
git add app/controllers tests/controllers
git commit -m "feat: isolate connection and firewall state per server"
```

### Task 3: Application shell, sidebar, and selected-server routing

**Files:**
- Create: `app/gui/__init__.py`
- Create: `app/gui/main_window.py`
- Create: `app/gui/server_sidebar.py`
- Create: `app/gui/widgets/__init__.py`
- Create: `app/gui/widgets/state_panel.py`
- Modify: `main.py`
- Create: `tests/gui/test_main_window.py`
- Create: `tests/gui/test_server_sidebar.py`

**Interfaces:**
- Consumes: `ServerController` signals and `ServerSessionView`
- Produces: `MainWindow(controller: ServerController)`
- Produces: `ServerSidebar.set_sessions(sessions, selected_id) -> None`
- Sidebar signals: `server_selected`, `connect_requested`, `disconnect_requested`, `reload_requested`

- [ ] **Step 1: Write failing shell and sidebar tests**

```python
from app.gui.main_window import MainWindow


def test_window_lists_profiles_without_connecting(qtbot, fake_server_controller):
    window = MainWindow(fake_server_controller)
    qtbot.addWidget(window)
    assert window.server_sidebar.server_ids() == ("web01", "db01", "test01")
    assert fake_server_controller.connect_calls == []


def test_selecting_server_routes_its_snapshot_only(qtbot, fake_server_controller):
    window = MainWindow(fake_server_controller)
    qtbot.addWidget(window)
    window.server_sidebar.select_server("db01")
    assert window.current_server_id == "db01"
    assert window.header_title.text() == "Database Server"
```

Test text-plus-icon status, disconnected/empty/error state panels, menu-based reload, and status bar busy messages.

- [ ] **Step 2: Run GUI shell tests and confirm failure**

Run on Windows PowerShell: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_main_window.py tests/gui/test_server_sidebar.py -v`

Expected: FAIL because GUI modules are missing.

- [ ] **Step 3: Implement the sidebar/content shell with initial tab containers**

Create a horizontal splitter with a fixed-minimum sidebar and expanding content. Add named Overview, Ports, Services, Zones, Interfaces, Rich Rules, and Logs tab containers; later tasks replace each container's initial state panel with its management widget. Render every connection state with icon plus text. Wire menu and sidebar signals to controllers without backend calls in widgets.

Update `main.main()` to build `QApplication`, portable paths, configuration, logger, scheduler, controller, and `MainWindow`; return the Qt exit code. Catch initial `ConfigurationError` before showing the window and display a credential-safe startup message.

- [ ] **Step 4: Run shell tests and a startup smoke test**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_main_window.py tests/gui/test_server_sidebar.py -v`

Expected: PASS.

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -c "from app.gui.main_window import MainWindow; print('GUI import OK')"`

Expected: `GUI import OK`.

- [ ] **Step 5: Commit the application shell**

```bash
git add main.py app/gui tests/gui/test_main_window.py tests/gui/test_server_sidebar.py
git commit -m "feat: add multi-server desktop application shell"
```

### Task 4: Host-key, sudo-password, confirmation, and error dialogs

**Files:**
- Create: `app/gui/dialogs/__init__.py`
- Create: `app/gui/dialogs/host_key_dialog.py`
- Create: `app/gui/dialogs/sudo_password_dialog.py`
- Create: `app/gui/dialogs/confirmation_dialog.py`
- Create: `app/gui/dialogs/error_dialog.py`
- Modify: `app/gui/main_window.py`
- Modify: `app/controllers/server_controller.py`
- Create: `tests/gui/test_security_dialogs.py`

**Interfaces:**
- Produces: `HostKeyDialog.confirmed() -> bool`
- Produces: `SudoPasswordDialog.take_password() -> str | None`
- Produces: `ChangePreview(server_name, host, operation, zone, resource, target, risk)`
- Produces: `ConfirmationDialog.confirmed() -> bool`
- Produces: `ErrorDialog.from_domain_error(error) -> ErrorDialog`

- [ ] **Step 1: Write failing dialog tests**

```python
def test_host_key_dialog_displays_sha256_and_requires_explicit_trust(qtbot, challenge):
    dialog = HostKeyDialog(challenge)
    qtbot.addWidget(dialog)
    assert challenge.fingerprint_sha256 in dialog.fingerprint_label.text()
    assert dialog.defaultButton() is dialog.cancel_button


def test_sudo_password_is_removed_from_widget_when_taken(qtbot):
    dialog = SudoPasswordDialog("Production Web Server")
    qtbot.addWidget(dialog)
    dialog.password_edit.setText("sudo-secret")
    assert dialog.take_password() == "sudo-secret"
    assert dialog.password_edit.text() == ""


def test_high_risk_confirmation_uses_apply_anyway_and_no_default_accept(qtbot, risky_preview):
    dialog = ConfirmationDialog(risky_preview)
    qtbot.addWidget(dialog)
    assert dialog.apply_button.text() == "Apply Anyway"
    assert dialog.defaultButton() is dialog.cancel_button
```

Add tests proving password text never appears in labels, error dialogs sanitize domain errors, changed-key dialogs have no trust action, and closing a sudo dialog cancels the waiting operation.

- [ ] **Step 2: Run dialog tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_security_dialogs.py -v`

Expected: FAIL because dialogs are missing.

- [ ] **Step 3: Implement typed dialogs and controller retry handshakes**

Unknown-host confirmation calls `HostKeyStore.trust()` only after acceptance, then schedules a new connection. Sudo-required results emit a request containing server ID, generation, and logical operation but no password; acceptance stores the password in that session and resubmits once. Authentication failure clears the cached value. Changed keys show a high-severity error with no replacement button.

- [ ] **Step 4: Run dialog and controller tests**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_security_dialogs.py tests/controllers/test_server_controller.py -v`

Expected: PASS, including cancel and stale-generation cases.

- [ ] **Step 5: Commit secure dialogs**

```bash
git add app/gui/dialogs app/gui/main_window.py app/controllers/server_controller.py tests/gui/test_security_dialogs.py tests/controllers/test_server_controller.py
git commit -m "feat: add explicit SSH trust and memory-only sudo prompts"
```

### Task 5: Overview and connection-test workflow

**Files:**
- Create: `app/gui/overview_tab.py`
- Modify: `app/gui/main_window.py`
- Modify: `app/controllers/server_controller.py`
- Create: `tests/gui/test_overview_tab.py`

**Interfaces:**
- Consumes: `ServerSessionView`, `FirewallSnapshot`, `ConnectionTestResult`
- Overview signals: `connect_requested`, `disconnect_requested`, `reconnect_requested`, `refresh_requested`, `reload_firewalld_requested`, `test_connection_requested`
- Produces: `OverviewTab.set_session(view: ServerSessionView) -> None`
- Produces: `OverviewTab.show_connection_test(result: ConnectionTestResult) -> None`

- [ ] **Step 1: Write failing overview tests**

```python
def test_overview_renders_connected_snapshot(qtbot, connected_session_view):
    tab = OverviewTab()
    qtbot.addWidget(tab)
    tab.set_session(connected_session_view)
    assert tab.hostname_value.text() == "web01"
    assert tab.firewalld_value.text() == "Running"
    assert tab.default_zone_value.text() == "public"


def test_busy_session_disables_only_mutating_controls(qtbot, busy_session_view):
    tab = OverviewTab()
    qtbot.addWidget(tab)
    tab.set_session(busy_session_view)
    assert not tab.reload_button.isEnabled()
    assert tab.disconnect_button.isEnabled()
```

Add tests for disconnected state, stopped/missing firewalld, stale state, test result PASS/FAIL rows, and no firewall mutation during connection testing.

- [ ] **Step 2: Run overview tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_overview_tab.py -v`

Expected: FAIL because `OverviewTab` is missing.

- [ ] **Step 3: Implement summary fields and controller wiring**

Use labeled values for server, host, port, user, connection, hostname, distribution, firewalld state/version, default zone, active zones, and assigned interfaces. Use a table for named connection-test checks. Disable actions from state and busy flags rather than optimistic widget-local toggles.

- [ ] **Step 4: Run overview and shell tests**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_overview_tab.py tests/gui/test_main_window.py -v`

Expected: PASS.

- [ ] **Step 5: Commit Overview**

```bash
git add app/gui/overview_tab.py app/gui/main_window.py app/controllers/server_controller.py tests/gui/test_overview_tab.py
git commit -m "feat: add server overview and connection testing"
```

### Task 6: Ports table model, filtering, and add dialog

**Files:**
- Create: `app/gui/models/__init__.py`
- Create: `app/gui/models/ports_model.py`
- Create: `app/gui/ports_tab.py`
- Create: `app/gui/dialogs/add_port_dialog.py`
- Create: `tests/gui/test_ports_model.py`
- Create: `tests/gui/test_add_port_dialog.py`

**Interfaces:**
- Produces: `PortRow(port, protocol, zone, runtime, permanent)`
- Produces: `PortsTableModel.set_rows(rows: Sequence[PortRow]) -> None`
- Produces: `merge_port_rows(snapshot: FirewallSnapshot, zone: str) -> tuple[PortRow, ...]`
- Produces: `AddPortRequest(zone, port, protocol, target)`
- Ports signals: `refresh_requested(zone)`, `add_requested()`, `remove_requested(row)`

- [ ] **Step 1: Write failing model tests for merged state and sorting**

```python
def test_merge_marks_runtime_and_permanent_independently(snapshot_with_split_ports):
    rows = merge_port_rows(snapshot_with_split_ports, "public")
    by_port = {(row.port, row.protocol): row for row in rows}
    assert by_port[("22", "tcp")].runtime and by_port[("22", "tcp")].permanent
    assert not by_port[("8000-8100", "tcp")].runtime
    assert by_port[("8000-8100", "tcp")].permanent


def test_model_exposes_required_columns(qtbot):
    model = PortsTableModel()
    assert [model.headerData(i, Qt.Horizontal) for i in range(model.columnCount())] == [
        "Port", "Protocol", "Zone", "Runtime", "Permanent"
    ]
```

- [ ] **Step 2: Write failing add-dialog validation tests**

```python
def test_add_dialog_defaults_to_runtime_and_permanent(qtbot):
    dialog = AddPortDialog(("public", "internal"), "public")
    qtbot.addWidget(dialog)
    assert dialog.target() is ApplyTarget.BOTH


def test_invalid_port_disables_add_and_shows_reason(qtbot):
    dialog = AddPortDialog(("public",), "public")
    qtbot.addWidget(dialog)
    dialog.port_edit.setText("22; id")
    assert not dialog.add_button.isEnabled()
    assert dialog.validation_label.text()
```

- [ ] **Step 3: Run Ports model/dialog tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_ports_model.py tests/gui/test_add_port_dialog.py -v`

Expected: FAIL because Ports modules are missing.

- [ ] **Step 4: Implement model, proxy filtering, tab layout, and dialog**

Use `QSortFilterProxyModel` for case-insensitive search across port, protocol, and zone. The view selector filters rows by runtime/permanent presence without changing source data. Use checkmark display plus accessible text for boolean columns. Populate zone choices only from the selected snapshot.

- [ ] **Step 5: Run focused GUI tests**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_ports_model.py tests/gui/test_add_port_dialog.py -v`

Expected: PASS for merging, sorting, searching, view filtering, selection state, range validation, protocol selection, and target defaults.

- [ ] **Step 6: Commit Ports presentation**

```bash
git add app/gui/models app/gui/ports_tab.py app/gui/dialogs/add_port_dialog.py tests/gui/test_ports_model.py tests/gui/test_add_port_dialog.py
git commit -m "feat: add table-based Ports management view"
```

### Task 7: Complete confirmed and verified Ports workflow

**Files:**
- Create: `app/controllers/firewall_controller.py`
- Modify: `app/gui/main_window.py`
- Modify: `app/gui/ports_tab.py`
- Create: `tests/controllers/test_firewall_controller.py`
- Create: `tests/gui/test_ports_workflow.py`

**Interfaces:**
- Produces: `FirewallController.preview_add_port(server_id, request) -> ChangePreview`
- Produces: `FirewallController.preview_remove_port(server_id, row, target) -> ChangePreview`
- Produces: `FirewallController.apply_add_port(...) -> JobHandle`
- Produces: `FirewallController.apply_remove_port(...) -> JobHandle`
- Controller signals: `operation_result(server_id, CompositeOperationResult)`, `snapshot_changed(server_id, FirewallSnapshot)`, `error_raised(server_id, error)`
- Test support in `tests/controllers/fakes.py`: `ImmediateJobHandle.run_synchronously_for_test() -> None`

- [ ] **Step 1: Write failing controller pipeline tests**

```python
def test_add_port_uses_current_inventory_and_exact_preview(firewall_controller, connected_session):
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)
    preview = firewall_controller.preview_add_port("web01", request)
    assert preview.operation == "Add Firewall Port"
    assert preview.resource == "8080/tcp"
    assert preview.target is ApplyTarget.BOTH


def test_remove_management_port_contains_lockout_warning(firewall_controller, connected_session):
    preview = firewall_controller.preview_remove_port(
        "web01", PortRow("22", "tcp", "public", True, True), ApplyTarget.BOTH
    )
    assert preview.risk.is_high


def test_apply_publishes_refreshed_verified_snapshot(firewall_controller, fake_service):
    request = AddPortRequest("public", "8080", "tcp", ApplyTarget.BOTH)
    fake_service.add_port_result = successful_composite_result()
    fake_service.next_snapshot = snapshot_with_port("8080", "tcp")
    handle = firewall_controller.apply_add_port("web01", request)
    handle.run_synchronously_for_test()
    assert firewall_controller.server_controller.session_view("web01").snapshot.has_port("public", "8080", "tcp", False)
```

Add rejection cases for disconnected server, stale/unknown zone, missing selection, busy server, cancelled confirmation, partial result, verification failure, and sudo-required resubmission.

- [ ] **Step 2: Run controller tests and confirm failure**

Run: `python -m pytest tests/controllers/test_firewall_controller.py -v`

Expected: FAIL because `FirewallController` is missing.

- [ ] **Step 3: Implement the controller pipeline without dialogs**

Keep preview creation pure. GUI code decides whether the user confirmed, then calls an apply method with that immutable preview/request. Revalidate the session generation and inventory immediately before enqueue. Service results refresh the snapshot before emitting completion.

- [ ] **Step 4: Write and run the end-to-end Qt workflow tests**

```python
def test_add_port_requires_confirmation_then_updates_table(qtbot, window, fake_service):
    window.select_server("web01")
    qtbot.mouseClick(window.ports_tab.add_button, Qt.LeftButton)
    fill_add_dialog(qtbot, port="8080", protocol="tcp", target=ApplyTarget.BOTH)
    accept_add_dialog(qtbot)
    assert_confirmation_preview(qtbot, resource="8080/tcp", target="Runtime + Permanent")
    accept_confirmation(qtbot)
    fake_service.finish_add_successfully()
    qtbot.waitUntil(lambda: window.ports_tab.contains("8080", "tcp"))
```

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_ports_workflow.py -v`

Expected: PASS for add, remove, partial result, lockout warning, cancel, busy state, refresh, search, and server switching.

- [ ] **Step 5: Run the full suite**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest -v`

Expected: all foundation, backend, controller, and GUI tests PASS.

- [ ] **Step 6: Commit the Ports workflow**

```bash
git add app/controllers/firewall_controller.py app/gui/main_window.py app/gui/ports_tab.py tests/controllers/test_firewall_controller.py tests/gui/test_ports_workflow.py
git commit -m "feat: add confirmed and verified port changes"
```

## Plan 3 Completion Check

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest -v`

Expected: all tests pass. Launch with a disposable configuration and confirm the window remains responsive while a fake delayed SSH job runs. Confirm `git status --short` is empty before beginning the remaining management UI and hardening plan.
