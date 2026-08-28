# Management UI and Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Zones, Services, Interfaces, structured Rich Rules, reload and logs workflows, then harden documentation, packaging, and acceptance behavior for the full MVP.

**Architecture:** Reuse the established table models, immutable previews, `FirewallController`, keyed scheduler, composite results, and typed dialogs. Each resource adds only its focused presentation model and controller methods while the tested backend remains the sole command and verification authority.

**Tech Stack:** Python 3.11+, PySide6, Paramiko, PyYAML, pytest, pytest-qt

**Spec:** `docs/superpowers/specs/2026-08-28-remote-firewalld-manager-design.md`

## Global Constraints

- Complete the first three plans and preserve their public interfaces.
- Use only zones, services, and interfaces present in the selected server's current inventory.
- Support Runtime, Permanent, and Runtime + Permanent wherever the approved spec requires them.
- Every write requires exact preview, confirmation, one execution per target, refresh, and verification.
- Never reload firewalld automatically after permanent changes.
- Rich rules remain structured; do not add a free-form command or rule editor.
- Keep one server's state, logs, errors, and credentials isolated from all others.
- README and examples must describe portable storage and plaintext SSH-password risk accurately.

---

## File Map

- `app/gui/zones_tab.py` and `app/gui/models/zones_model.py`: runtime/permanent zone inventory and default-zone changes.
- `app/gui/services_tab.py` and `app/gui/models/services_model.py`: allowed and available services.
- `app/gui/interfaces_tab.py` and `app/gui/models/interfaces_model.py`: interface assignments.
- `app/gui/rich_rules_tab.py` and `app/gui/models/rich_rules_model.py`: structured rule display and actions.
- `app/gui/dialogs/add_service_dialog.py`: inventory-constrained service request.
- `app/gui/dialogs/change_interface_dialog.py`: exact current/new zone preview input.
- `app/gui/dialogs/rich_rule_dialog.py`: structured address/service/port/action request.
- `app/gui/logs_tab.py`: sanitized per-server log view.
- `README.md`: installation, portable configuration, trust, sudo, use, testing, and troubleshooting.

### Task 1: Zones view and default-zone changes

**Files:**
- Create: `app/gui/models/zones_model.py`
- Create: `app/gui/zones_tab.py`
- Modify: `app/controllers/firewall_controller.py`
- Modify: `app/gui/main_window.py`
- Create: `tests/gui/test_zones_tab.py`
- Create: `tests/controllers/test_zone_workflow.py`

**Interfaces:**
- Produces: `ZoneRow(name, active, interfaces, sources, services, ports, protocols, masquerade, forwarding, rich_rule_count)`
- Produces: `ZonesModel.set_zones(zones: Sequence[ZoneState]) -> None`
- Produces: `FirewallController.preview_set_default_zone(server_id, new_zone) -> ChangePreview`
- Produces: `FirewallController.apply_set_default_zone(server_id, new_zone, target) -> JobHandle`

- [ ] **Step 1: Write failing Zones model and rendering tests**

```python
def test_zone_rows_preserve_runtime_or_permanent_details(snapshot):
    rows = zone_rows(snapshot, permanent=False)
    public = next(row for row in rows if row.name == "public")
    assert public.active
    assert public.interfaces == ("eth0",)
    assert "ssh" in public.services


def test_zone_tab_switches_runtime_and_permanent_without_mixing(qtbot, snapshot):
    tab = ZonesTab()
    qtbot.addWidget(tab)
    tab.set_snapshot(snapshot)
    tab.view_combo.setCurrentText("Permanent")
    assert tab.model.zones() == snapshot.permanent_zones
```

- [ ] **Step 2: Write failing default-zone controller tests**

```python
def test_default_zone_preview_names_current_and_new_zone(controller, connected_session):
    preview = controller.preview_set_default_zone("web01", "internal")
    assert preview.resource == "public → internal"


def test_unknown_default_zone_is_rejected(controller, connected_session):
    with pytest.raises(InvalidFirewallArgumentError):
        controller.preview_set_default_zone("web01", "invented")
```

- [ ] **Step 3: Run focused tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_zones_tab.py tests/controllers/test_zone_workflow.py -v`

Expected: FAIL because Zones modules and controller methods are missing.

- [ ] **Step 4: Implement Zones table/detail pane and confirmed default-zone workflow**

Show one row per zone and a read-only details pane for the selected row. The active flag comes from runtime active-zone data; permanent view labels activity as runtime-derived. Default-zone selection uses only available zone names, displays current and new values, then delegates execution and verification to `FirewalldService`.

- [ ] **Step 5: Run Zones tests**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_zones_tab.py tests/controllers/test_zone_workflow.py -v`

Expected: PASS for empty, runtime, permanent, default-zone confirmation, cancel, failure, and refresh states.

- [ ] **Step 6: Commit Zones management**

```bash
git add app/gui/models/zones_model.py app/gui/zones_tab.py app/controllers/firewall_controller.py app/gui/main_window.py tests/gui/test_zones_tab.py tests/controllers/test_zone_workflow.py
git commit -m "feat: add zone inspection and default-zone changes"
```

### Task 2: Services management

**Files:**
- Create: `app/gui/models/services_model.py`
- Create: `app/gui/services_tab.py`
- Create: `app/gui/dialogs/add_service_dialog.py`
- Modify: `app/controllers/firewall_controller.py`
- Modify: `app/gui/main_window.py`
- Create: `tests/gui/test_services_workflow.py`

**Interfaces:**
- Produces: `ServiceRow(name, zone, runtime, permanent)`
- Produces: `AddServiceRequest(zone, service, target)`
- Produces: `preview_add_service`, `preview_remove_service`, `apply_add_service`, `apply_remove_service`

- [ ] **Step 1: Write failing merged-service and inventory-dialog tests**

```python
def test_service_rows_merge_runtime_and_permanent(snapshot_with_split_services):
    rows = merge_service_rows(snapshot_with_split_services, "public")
    ssh = next(row for row in rows if row.name == "ssh")
    assert ssh.runtime and ssh.permanent


def test_add_service_dialog_lists_remote_services_only(qtbot):
    dialog = AddServiceDialog(("http", "https", "ssh"), ("public",), "public")
    qtbot.addWidget(dialog)
    assert dialog.service_names() == ("http", "https", "ssh")
```

- [ ] **Step 2: Write failing lockout and apply tests**

```python
def test_removing_ssh_service_requires_high_risk_confirmation(controller, connected_session):
    preview = controller.preview_remove_service("web01", ServiceRow("ssh", "public", True, True), ApplyTarget.BOTH)
    assert preview.risk.is_high


def test_add_service_refreshes_verified_rows(qtbot, window, fake_service):
    drive_add_service(window, "public", "https", ApplyTarget.BOTH)
    fake_service.finish_add_service_successfully()
    qtbot.waitUntil(lambda: window.services_tab.contains("https", "public"))
```

- [ ] **Step 3: Run Services tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_services_workflow.py -v`

Expected: FAIL because Services modules are missing.

- [ ] **Step 4: Implement service table, remote-inventory dialog, and controller methods**

Merge runtime and permanent service presence like Ports. Exclude services already present for the selected targets from the add dialog. Require a row for removal, use the standard confirmation pipeline, and invoke lockout analysis for `ssh`.

- [ ] **Step 5: Run Services tests and commit**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_services_workflow.py -v`

Expected: PASS for list, filter, add, remove, partial, risk, and server-switch cases.

```bash
git add app/gui/models/services_model.py app/gui/services_tab.py app/gui/dialogs/add_service_dialog.py app/controllers/firewall_controller.py app/gui/main_window.py tests/gui/test_services_workflow.py
git commit -m "feat: add verified firewall service management"
```

### Task 3: Interface-zone management

**Files:**
- Create: `app/gui/models/interfaces_model.py`
- Create: `app/gui/interfaces_tab.py`
- Create: `app/gui/dialogs/change_interface_dialog.py`
- Modify: `app/controllers/firewall_controller.py`
- Modify: `app/gui/main_window.py`
- Create: `tests/gui/test_interfaces_workflow.py`

**Interfaces:**
- Produces: `InterfaceRow(name, runtime_zone, permanent_zone, active)`
- Produces: `ChangeInterfaceRequest(interface, current_zone, new_zone, target)`
- Produces: `preview_change_interface_zone` and `apply_change_interface_zone`

- [ ] **Step 1: Write failing interface-model and dialog tests**

```python
def test_interface_rows_merge_zone_assignments(snapshot):
    row = next(row for row in interface_rows(snapshot) if row.name == "eth0")
    assert row.runtime_zone == "public"
    assert row.active


def test_change_dialog_excludes_current_zone(qtbot):
    dialog = ChangeInterfaceDialog("eth0", "public", ("public", "internal", "dmz"))
    qtbot.addWidget(dialog)
    assert dialog.available_zones() == ("internal", "dmz")
```

- [ ] **Step 2: Write failing risk and inventory tests**

```python
def test_moving_active_management_interface_is_high_risk(controller, connected_session):
    request = ChangeInterfaceRequest("eth0", "public", "internal", ApplyTarget.BOTH)
    assert controller.preview_change_interface_zone("web01", request).risk.is_high


def test_undiscovered_interface_is_rejected(controller, connected_session):
    request = ChangeInterfaceRequest("eth99", "public", "internal", ApplyTarget.RUNTIME)
    with pytest.raises(InvalidFirewallArgumentError):
        controller.preview_change_interface_zone("web01", request)
```

- [ ] **Step 3: Run Interface tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_interfaces_workflow.py -v`

Expected: FAIL because Interface modules are missing.

- [ ] **Step 4: Implement table, dialog, risk preview, and verified controller call**

Populate interfaces only from the snapshot. Treat movement of any active interface as potentially management-affecting because the client cannot perfectly identify the remote route's egress interface. State this limitation in the warning.

- [ ] **Step 5: Run Interface tests and commit**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_interfaces_workflow.py -v`

Expected: PASS for runtime/permanent display, allowed zones, risk, confirmation, partial result, and refresh.

```bash
git add app/gui/models/interfaces_model.py app/gui/interfaces_tab.py app/gui/dialogs/change_interface_dialog.py app/controllers/firewall_controller.py app/gui/main_window.py tests/gui/test_interfaces_workflow.py
git commit -m "feat: manage interface zone assignments safely"
```

### Task 4: Structured Rich Rules management

**Files:**
- Create: `app/gui/models/rich_rules_model.py`
- Create: `app/gui/rich_rules_tab.py`
- Create: `app/gui/dialogs/rich_rule_dialog.py`
- Modify: `app/controllers/firewall_controller.py`
- Modify: `app/gui/main_window.py`
- Create: `tests/gui/test_rich_rules_workflow.py`

**Interfaces:**
- Produces: `RichRuleRow(zone, summary, runtime, permanent, rule)`
- Produces: `RichRuleRequest(zone, source, destination, service, port, protocol, action, target)`
- Produces: `preview_add_rich_rule`, `preview_remove_rich_rule`, `apply_add_rich_rule`, `apply_remove_rich_rule`

- [ ] **Step 1: Write failing structured-dialog validation tests**

```python
def test_rule_requires_exactly_one_service_or_port(qtbot):
    dialog = RichRuleDialog(("public",), ("ssh", "http"), "public")
    qtbot.addWidget(dialog)
    dialog.service_combo.setCurrentText("ssh")
    dialog.port_edit.setText("22")
    assert not dialog.add_button.isEnabled()


def test_rule_dialog_rejects_shell_shaped_address(qtbot):
    dialog = RichRuleDialog(("public",), ("ssh",), "public")
    qtbot.addWidget(dialog)
    dialog.source_edit.setText("192.0.2.1; id")
    assert not dialog.add_button.isEnabled()


def test_rule_dialog_has_no_free_form_editor(qtbot):
    dialog = RichRuleDialog(("public",), ("ssh",), "public")
    assert not hasattr(dialog, "advanced_rule_edit")
```

- [ ] **Step 2: Write failing merge, preview, and risk tests**

```python
def test_rich_rule_rows_merge_exact_structured_rules(snapshot):
    rows = merge_rich_rule_rows(snapshot, "public")
    ssh_rule = next(row for row in rows if "ssh" in row.summary)
    assert ssh_rule.runtime and ssh_rule.permanent


def test_removing_ssh_permit_rule_is_high_risk(controller, connected_session, ssh_rule_row):
    assert controller.preview_remove_rich_rule("web01", ssh_rule_row, ApplyTarget.BOTH).risk.is_high
```

- [ ] **Step 3: Run Rich Rules tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_rich_rules_workflow.py -v`

Expected: FAIL because Rich Rules modules are missing.

- [ ] **Step 4: Implement structured fields and exact-rule removal**

Allow optional source and destination networks, exactly one of service or port, protocol only with port, and actions accept/reject/drop. Infer IPv4 or IPv6 family from provided networks; reject mixed families. Removal passes the exact structured rule value already returned by the backend, never editable table text.

- [ ] **Step 5: Run Rich Rules tests and commit**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_rich_rules_workflow.py -v`

Expected: PASS for structured validation, merging, add/remove, risk, target results, and absence of arbitrary input.

```bash
git add app/gui/models/rich_rules_model.py app/gui/rich_rules_tab.py app/gui/dialogs/rich_rule_dialog.py app/controllers/firewall_controller.py app/gui/main_window.py tests/gui/test_rich_rules_workflow.py
git commit -m "feat: add structured rich-rule management"
```

### Task 5: firewalld reload and per-server Logs tab

**Files:**
- Create: `app/gui/logs_tab.py`
- Modify: `app/gui/overview_tab.py`
- Modify: `app/gui/main_window.py`
- Modify: `app/controllers/firewall_controller.py`
- Modify: `app/controllers/server_controller.py`
- Create: `tests/gui/test_reload_and_logs.py`

**Interfaces:**
- Produces: `FirewallController.preview_reload(server_id) -> ChangePreview`
- Produces: `FirewallController.apply_reload(server_id) -> JobHandle`
- Produces: `LogsTab.set_entries(entries: Sequence[str]) -> None`
- Logs signals: `clear_requested(server_id)`, `refresh_requested(server_id)`, `copy_requested(server_id)`

- [ ] **Step 1: Write failing reload tests**

```python
def test_reload_preview_warns_runtime_changes_can_disappear(controller, connected_session):
    preview = controller.preview_reload("web01")
    assert "runtime-only changes may disappear" in preview.warning.lower()


def test_reload_refreshes_snapshot_after_success(controller, fake_service):
    fake_service.reload_result = successful_composite_result()
    fake_service.next_snapshot = make_snapshot(default_zone="internal")
    handle = controller.apply_reload("web01")
    handle.run_synchronously_for_test()
    assert controller.server_controller.session_view("web01").snapshot.default_zone == "internal"
```

- [ ] **Step 2: Write failing log-isolation and copy tests**

```python
def test_logs_tab_displays_selected_server_only(qtbot, window, server_log_buffer):
    server_log_buffer.append_message("web01", "connected web01")
    server_log_buffer.append_message("db01", "connected db01")
    window.select_server("web01")
    assert "connected web01" in window.logs_tab.toPlainText()
    assert "connected db01" not in window.logs_tab.toPlainText()


def test_clear_view_does_not_delete_rotating_log(qtbot, logs_tab, log_file):
    logs_tab.clear_button.click()
    assert logs_tab.toPlainText() == ""
    assert log_file.exists()
```

- [ ] **Step 3: Run reload/log tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_reload_and_logs.py -v`

Expected: FAIL because Logs tab and reload controller methods are missing.

- [ ] **Step 4: Implement confirmed reload and sanitized log actions**

Reload uses the standard confirmation dialog, calls the service once, and loads a fresh snapshot. Logs update on selection and controller events. Copy uses `QApplication.clipboard()` with only display-buffer text. Refresh rereads the in-memory buffer; it does not parse or expose arbitrary log files.

- [ ] **Step 5: Run reload/log and full GUI tests**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/gui/test_reload_and_logs.py -v`

Expected: PASS for confirmation, cancel, failure, refresh, server isolation, clear, and copy.

- [ ] **Step 6: Commit reload and Logs**

```bash
git add app/gui/logs_tab.py app/gui/overview_tab.py app/gui/main_window.py app/controllers tests/gui/test_reload_and_logs.py
git commit -m "feat: add confirmed reload and isolated log views"
```

### Task 6: README, startup integration, and clean-environment verification

**Files:**
- Modify: `README.md`
- Modify: `main.py`
- Modify: `requirements.txt`
- Create: `.gitignore`
- Create: `tests/test_startup.py`

**Interfaces:**
- Produces documented command: `python main.py`
- Produces documented test command: `python -m pytest -v`
- Produces startup behavior for missing/invalid `config.yaml` without a traceback or credential disclosure

- [ ] **Step 1: Write failing startup tests**

```python
def test_bootstrap_reports_missing_config_without_starting_connections(tmp_path, monkeypatch):
    result = bootstrap_for_test(tmp_path / "main.py")
    assert not result.started
    assert "config.yaml" in result.safe_error
    assert result.connection_attempts == 0


def test_startup_error_never_contains_yaml_password(tmp_path):
    config = tmp_path / "config.yaml"
    config.write_text("servers: [{id: x, password: startup-secret}]", encoding="utf-8")
    result = bootstrap_for_test(tmp_path / "main.py")
    assert "startup-secret" not in result.safe_error
```

- [ ] **Step 2: Run startup tests and confirm failure**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/test_startup.py -v`

Expected: FAIL because testable bootstrap separation is missing.

- [ ] **Step 3: Extract deterministic bootstrap and finish dependency declarations**

Create a testable `build_application(paths, client_factory=paramiko.SSHClient)` path that loads config, configures redaction with SSH passwords, creates controllers and the window, and does not connect. Keep `main.main()` limited to constructing `QApplication`, invoking bootstrap, showing a safe startup dialog on error, and entering the event loop.

Pin lower bounds compatible with Python 3.11 rather than exact patch versions. Add `.venv/`, `__pycache__/`, `.pytest_cache/`, `config.yaml`, `known_hosts`, `known_hosts.tmp`, `logs/`, coverage files, and Qt-generated artifacts to `.gitignore`.

- [ ] **Step 4: Replace README with complete portable-use documentation**

Document project purpose, a reserved screenshots section, Windows-primary support, Python 3.11+, virtual environment activation on Windows/Linux/macOS, installation, copying `config.example.yaml` to `config.yaml`, all YAML fields, plaintext SSH-password risk, app-local host keys, changed-key recovery as a deliberate manual file edit, root/passwordless/password-prompt sudo behavior, scoped sudoers guidance, running, testing, optional disposable-host testing, log location, and troubleshooting for every connection status.

State explicitly that sudo passwords are memory-only until disconnect and that Python does not guarantee physical memory zeroization. State that the application offers no generic command execution.

- [ ] **Step 5: Run startup and full automated tests**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/test_startup.py -v`

Expected: PASS.

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest -v`

Expected: all tests PASS with no network.

- [ ] **Step 6: Verify installation from a clean Windows virtual environment**

Run from the repository directory:

```powershell
py -3.11 -m venv .venv-clean
.\.venv-clean\Scripts\python.exe -m pip install -r requirements.txt
$env:QT_QPA_PLATFORM='offscreen'
.\.venv-clean\Scripts\python.exe -m pytest -v
```

Expected: dependency installation succeeds and all tests PASS. Remove `.venv-clean` only after resolving and validating its absolute repository-local path.

- [ ] **Step 7: Commit documentation and startup hardening**

```bash
git add README.md main.py requirements.txt .gitignore tests/test_startup.py
git commit -m "docs: complete portable setup and security guidance"
```

### Task 7: Acceptance scenario and final security regression

**Files:**
- Create: `tests/acceptance/test_multi_server_scenario.py`
- Create: `tests/security/test_credential_redaction.py`
- Create: `tests/security/test_closed_command_surface.py`
- Create: `docs/manual-acceptance-checklist.md`

**Interfaces:**
- Consumes the complete application through fake SSH/service adapters.
- Produces an offline automated acceptance scenario and an opt-in disposable-host checklist.
- Test harness produces: `with_servers`, `with_credentials`, `connect`, `select`, `add_port`, `remove_port`, `port_row`, `simulate_auth_and_sudo_failures`, `visible_text`, and `error_text`.

- [ ] **Step 1: Write the automated multi-server acceptance test**

```python
def test_three_server_port_lifecycle_remains_isolated(qtbot, application_harness):
    app = application_harness.with_servers("web01", "db01", "test01")
    app.connect("web01")
    app.add_port("web01", "public", "8080", "tcp", ApplyTarget.BOTH)
    assert app.port_row("web01", "8080", "tcp").runtime
    assert app.port_row("web01", "8080", "tcp").permanent

    app.connect("db01")
    assert app.port_row("db01", "8080", "tcp") is None
    app.select("web01")
    assert app.port_row("web01", "8080", "tcp") is not None

    app.remove_port("web01", "public", "8080", "tcp", ApplyTarget.BOTH)
    assert app.port_row("web01", "8080", "tcp") is None
```

Extend the same test module with readable SSH failure, partial runtime/permanent result, service add/remove, zone display, interface move warning, rich-rule add/remove, reload warning, and management-port lockout warning.

- [ ] **Step 2: Write credential and command-surface regression tests**

```python
def test_all_logs_errors_and_visible_widgets_exclude_credentials(application_harness, caplog):
    app = application_harness.with_credentials(ssh="ssh-secret", sudo="sudo-secret")
    app.simulate_auth_and_sudo_failures()
    combined = caplog.text + app.visible_text() + app.error_text()
    assert "ssh-secret" not in combined
    assert "sudo-secret" not in combined


def test_gui_and_controllers_expose_no_arbitrary_command_entrypoint():
    def public_callable_names(*types):
        return {
            name
            for type_ in types
            for name in dir(type_)
            if not name.startswith("_") and callable(getattr(type_, name))
        }

    forbidden = {"run_command", "execute_shell", "terminal", "command_text"}
    assert forbidden.isdisjoint(public_callable_names(MainWindow, ServerController, FirewallController))
```

- [ ] **Step 3: Run acceptance and security tests and fix any discovered integration defect test-first**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest tests/acceptance tests/security -v`

Expected: PASS. For any failure, first reduce it to a focused failing test in the owning module, then make the minimal implementation correction and rerun both the focused test and this command.

- [ ] **Step 4: Write the disposable-host manual checklist**

Translate the specification's 38-step acceptance flow into checkboxes. Require disposable hosts, backups or console access, three profiles, firewalld 2.x, runtime/permanent add and remove, simulated SSH failure, host-key unknown/change tests, password log search, partial-result simulation, and explicit evidence capture. Mark every firewall-mutating step as unsafe for production testing.

- [ ] **Step 5: Run the complete final verification**

Run: `$env:QT_QPA_PLATFORM='offscreen'; python -m pytest -v`

Expected: all tests PASS.

Run: `python -m compileall -q main.py app tests`

Expected: exit code 0.

Run: `git diff --check`

Expected: no output.

- [ ] **Step 6: Commit final acceptance coverage**

```bash
git add tests/acceptance tests/security docs/manual-acceptance-checklist.md
git commit -m "test: cover complete remote firewall acceptance flow"
```

## Plan 4 Completion Check

Run the full automated suite in the clean Windows environment, then perform the manual checklist only against disposable servers. Confirm all test results, manual evidence, credential scans, `git diff --check`, and `git status --short` before declaring the MVP complete.
