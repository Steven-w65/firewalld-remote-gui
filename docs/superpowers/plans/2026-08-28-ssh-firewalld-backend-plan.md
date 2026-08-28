# SSH and firewalld Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a host-key-safe Paramiko transport and an independently testable, allowlisted firewalld backend with sudo, parsing, composite operations, and post-write verification.

**Architecture:** One `SSHManager` owns each server's Paramiko client and accepts only trusted `CommandSpec` values. Builders create allowlisted argument tuples, parsers create immutable firewall models, and `FirewalldService` coordinates reads and verified writes through an injected executor.

**Tech Stack:** Python 3.11+, Paramiko, PyYAML, pytest

**Spec:** `docs/superpowers/specs/2026-08-28-remote-firewalld-manager-design.md`

## Global Constraints

- Complete `2026-08-28-foundation-configuration-plan.md` first.
- Target modern `firewalld` 2.x remote installations.
- Never silently trust an unknown or changed SSH host key.
- Accept only `CommandSpec`; expose no arbitrary command interface to GUI or controllers.
- Try passwordless sudo first; prompt orchestration happens outside workers; send a supplied sudo password only over channel stdin.
- Never place SSH or sudo passwords in commands, results, logs, or exceptions.
- Treat runtime and permanent executions and verification independently.
- Never retry a write automatically.
- Keep normal tests entirely mocked and offline.

---

## File Map

- `app/ssh/host_keys.py`: application-specific known-hosts loading, challenges, and atomic trust.
- `app/ssh/ssh_manager.py`: connection lifecycle and trusted command execution.
- `app/ssh/channel_runner.py`: timeout-aware Paramiko channel protocol.
- `app/firewalld/command_builder.py`: approved firewall command specifications.
- `app/firewalld/system_commands.py`: approved hostname/distribution probes.
- `app/firewalld/renderer.py`: single safe argument renderer and sudo wrapper.
- `app/firewalld/parser.py`: pure firewalld output parsers.
- `app/firewalld/service.py`: reads, writes, composite results, refresh, and verification.
- `app/firewalld/lockout.py`: pure conservative lockout-risk analysis.

### Task 1: Host-key store and connection challenges

**Files:**
- Create: `app/ssh/__init__.py`
- Create: `app/ssh/host_keys.py`
- Modify: `app/utils/errors.py`
- Create: `tests/ssh/test_host_keys.py`

**Interfaces:**
- Consumes: `PortablePaths.known_hosts_file`
- Produces: `HostKeyChallenge(host, port, algorithm, fingerprint_sha256, key)`
- Produces: `HostKeyStore.load() -> paramiko.HostKeys`
- Produces: `HostKeyStore.verify(host: str, port: int, key: PKey) -> None`
- Produces: `HostKeyStore.trust(challenge: HostKeyChallenge) -> None`
- Raises: `UnknownHostKeyError(challenge)` and `ChangedHostKeyError(host, port, expected_fingerprint, actual_fingerprint)`

- [ ] **Step 1: Write failing tests for matching, unknown, changed, and persisted keys**

```python
import paramiko
import pytest

from app.ssh.host_keys import HostKeyStore
from app.utils.errors import ChangedHostKeyError, UnknownHostKeyError


def test_unknown_key_exposes_sha256_challenge_without_trusting(tmp_path):
    store = HostKeyStore(tmp_path / "known_hosts")
    key = paramiko.RSAKey.generate(1024)

    with pytest.raises(UnknownHostKeyError) as caught:
        store.verify("example.test", 22, key)

    assert caught.value.challenge.algorithm == key.get_name()
    assert caught.value.challenge.fingerprint_sha256.startswith("SHA256:")
    assert not (tmp_path / "known_hosts").exists()


def test_trusted_key_round_trips_and_changed_key_is_rejected(tmp_path):
    store = HostKeyStore(tmp_path / "known_hosts")
    first = paramiko.RSAKey.generate(1024)
    challenge = store.challenge("example.test", 2222, first)
    store.trust(challenge)
    HostKeyStore(tmp_path / "known_hosts").verify("example.test", 2222, first)

    with pytest.raises(ChangedHostKeyError):
        store.verify("example.test", 2222, paramiko.RSAKey.generate(1024))
```

- [ ] **Step 2: Run the host-key tests and confirm failure**

Run: `python -m pytest tests/ssh/test_host_keys.py -v`

Expected: FAIL because `HostKeyStore` is missing.

- [ ] **Step 3: Implement OpenSSH host naming, fingerprints, and atomic persistence**

Use `host` for port 22 and `[host]:port` for nonstandard ports. Compute SHA-256 fingerprints from `key.asbytes()` using base64 without trailing `=`. Write a complete temporary file in the same directory, flush it, then replace `known_hosts`. Do not provide a replace-changed-key method.

- [ ] **Step 4: Run focused tests**

Run: `python -m pytest tests/ssh/test_host_keys.py -v`

Expected: PASS, including corrupt-file errors that do not erase the existing file.

- [ ] **Step 5: Commit host-key trust**

```bash
git add app/ssh app/utils/errors.py tests/ssh/test_host_keys.py
git commit -m "feat: verify and persist explicit SSH host trust"
```

### Task 2: Safe command rendering and allowlisted builders

**Files:**
- Create: `app/firewalld/__init__.py`
- Create: `app/firewalld/renderer.py`
- Create: `app/firewalld/command_builder.py`
- Create: `app/firewalld/system_commands.py`
- Create: `tests/firewalld/test_command_builder.py`
- Create: `tests/firewalld/test_renderer.py`

**Interfaces:**
- Consumes: `CommandSpec`
- Produces: `render_command(spec: CommandSpec) -> str`
- Produces: `render_sudo(spec: CommandSpec, mode: Literal["noninteractive", "stdin"]) -> str`
- Produces: `FirewalldCommandBuilder` static methods listed below
- Produces: `SystemCommandBuilder.hostname()`, `.distribution()`, `.effective_uid()`

- [ ] **Step 1: Write failing builder tests for every approved operation**

```python
from app.firewalld.command_builder import FirewalldCommandBuilder as Builder


def test_add_port_builds_runtime_and_permanent_arguments():
    runtime = Builder.add_port("public", "8080", "tcp", permanent=False)
    permanent = Builder.add_port("public", "8080", "tcp", permanent=True)
    assert runtime.argv == ("firewall-cmd", "--zone=public", "--add-port=8080/tcp")
    assert permanent.argv == ("firewall-cmd", "--permanent", "--zone=public", "--add-port=8080/tcp")


def test_structured_rich_rule_never_accepts_shell_text():
    rule = Builder.add_rich_rule(
        zone="public",
        source="192.0.2.0/24",
        destination=None,
        service="ssh",
        port=None,
        protocol=None,
        action="accept",
        permanent=False,
    )
    assert rule.argv[-1] == '--add-rich-rule=rule family="ipv4" source address="192.0.2.0/24" service name="ssh" accept'
```

Add exact-argv tests for state, version, zones, active zones, default zone, set default zone, zone details, list/add/remove ports, available and zone services, add/remove service, list/add/remove rich rules, interface assignment, and reload.

- [ ] **Step 2: Write failing renderer tests**

```python
from app.firewalld.renderer import render_command, render_sudo
from app.models.command import CommandSpec


def test_renderer_quotes_each_argument_as_one_shell_word():
    spec = CommandSpec("probe", ("printf", "%s", "a value; id"), False)
    rendered = render_command(spec)
    assert rendered == "printf %s 'a value; id'"


def test_sudo_password_is_not_part_of_rendered_command():
    spec = CommandSpec("state", ("firewall-cmd", "--state"), True)
    assert render_sudo(spec, "noninteractive") == "sudo -n -- firewall-cmd --state"
    assert render_sudo(spec, "stdin") == "sudo -S -p '' -- firewall-cmd --state"
```

- [ ] **Step 3: Run builder and renderer tests and confirm failure**

Run: `python -m pytest tests/firewalld/test_command_builder.py tests/firewalld/test_renderer.py -v`

Expected: FAIL during import.

- [ ] **Step 4: Implement strict builders and the single renderer**

Use the validators from Plan 1 before building. Keep `CommandSpec.argv` as data until the SSH boundary. Render with `shlex.join`. Build rich rules exclusively from structured values in a deterministic clause order: family, source, destination, service or port/protocol, action.

System probes use fixed commands: `hostname`, `cat /etc/os-release`, and `id -u`. They set `requires_privilege=False`.

- [ ] **Step 5: Run focused command tests**

Run: `python -m pytest tests/firewalld/test_command_builder.py tests/firewalld/test_renderer.py -v`

Expected: PASS for all logical operations and injection-shaped arguments.

- [ ] **Step 6: Commit the closed command surface**

```bash
git add app/firewalld tests/firewalld/test_command_builder.py tests/firewalld/test_renderer.py
git commit -m "feat: build allowlisted firewalld commands safely"
```

### Task 3: Timeout-aware SSH manager and sudo execution

**Files:**
- Create: `app/ssh/channel_runner.py`
- Create: `app/ssh/ssh_manager.py`
- Modify: `app/utils/errors.py`
- Create: `tests/ssh/fakes.py`
- Create: `tests/ssh/test_ssh_manager.py`

**Interfaces:**
- Consumes: `ServerConfig`, `HostKeyStore`, `CommandSpec`
- Produces: `SSHManager.connect() -> None`
- Produces: `SSHManager.disconnect() -> None`
- Produces: `SSHManager.is_connected() -> bool`
- Produces: `SSHManager.execute_command(spec: CommandSpec, sudo_password: str | None = None) -> CommandResult`
- Raises: safe SSH domain errors and `SudoAuthenticationRequiredError`

- [ ] **Step 1: Write failing connection error-mapping tests**

```python
import paramiko
import pytest

from app.ssh.ssh_manager import SSHManager
from app.utils.errors import SSHAuthenticationError, SSHConnectionError


def test_authentication_failure_maps_to_safe_domain_error(server_config, host_key_store, fake_client):
    fake_client.connect_error = paramiko.AuthenticationException()
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)
    with pytest.raises(SSHAuthenticationError, match="authentication failed") as caught:
        manager.connect()
    assert server_config.password not in str(caught.value)


def test_dns_failure_does_not_include_password(server_config, host_key_store, fake_client):
    fake_client.connect_error = OSError("name lookup failed")
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)
    with pytest.raises(SSHConnectionError) as caught:
        manager.connect()
    assert server_config.password not in str(caught.value)
```

- [ ] **Step 2: Write failing execution and sudo tests**

```python
import pytest

from app.models.command import CommandSpec
from app.utils.errors import CommandTimeoutError, SudoAuthenticationRequiredError


def test_passwordless_sudo_is_attempted_first(connected_manager, fake_client):
    fake_client.queue_result(0, "running\n", "")
    result = connected_manager.execute_command(CommandSpec("state", ("firewall-cmd", "--state"), True))
    assert result.success
    assert fake_client.commands == ["sudo -n -- firewall-cmd --state"]


def test_required_sudo_password_returns_typed_signal(connected_manager, fake_client):
    fake_client.queue_result(1, "", "sudo: a password is required")
    with pytest.raises(SudoAuthenticationRequiredError):
        connected_manager.execute_command(CommandSpec("state", ("firewall-cmd", "--state"), True))


def test_supplied_sudo_password_uses_stdin_not_command(connected_manager, fake_client):
    fake_client.queue_result(0, "running\n", "")
    connected_manager.execute_command(CommandSpec("state", ("firewall-cmd", "--state"), True), "sudo-secret")
    assert "sudo-secret" not in fake_client.commands[-1]
    assert fake_client.stdin_writes[-1] == "sudo-secret\n"
```

Add tests for root bypass, passwordless sudo, bad sudo password, connection refusal, DNS failure, connect timeout, command timeout, remote EOF, disconnect idempotency, and per-server result metadata.

- [ ] **Step 3: Run SSH tests and confirm failure**

Run: `python -m pytest tests/ssh/test_ssh_manager.py -v`

Expected: FAIL because `SSHManager` and fakes are missing.

- [ ] **Step 4: Implement connection lifecycle and injected channel execution**

Load and verify host keys exclusively through the application `HostKeyStore`. Configure Paramiko without an auto-add policy. Map exceptions to domain errors whose messages contain server ID and category, never credentials.

For commands, render plain commands when privilege is unnecessary or username is `root`. Otherwise render `sudo -n`. If a password is supplied, render `sudo -S -p ''`, open a channel without a PTY, write the password plus newline to stdin, then close stdin. Detect only canonical sudo password-required/authentication-failure messages and keep raw stderr in the sanitized `CommandResult` for noncredential firewall errors.

Use monotonic deadlines in `channel_runner.py`; on timeout close the channel and raise `CommandTimeoutError`.

- [ ] **Step 5: Run SSH tests**

Run: `python -m pytest tests/ssh/test_ssh_manager.py -v`

Expected: PASS for all mocked connection, timeout, host-key, and sudo cases.

- [ ] **Step 6: Commit SSH execution**

```bash
git add app/ssh app/utils/errors.py tests/ssh
git commit -m "feat: execute approved commands over isolated SSH sessions"
```

### Task 4: firewalld output parsers

**Files:**
- Create: `app/firewalld/parser.py`
- Modify: `app/utils/errors.py`
- Create: `tests/firewalld/fixtures/zone_public.txt`
- Create: `tests/firewalld/fixtures/active_zones.txt`
- Create: `tests/firewalld/test_parser.py`

**Interfaces:**
- Produces: `parse_words(output: str) -> tuple[str, ...]`
- Produces: `parse_active_zones(output: str) -> dict[str, tuple[str, ...]]`
- Produces: `parse_zone_state(name: str, output: str, permanent: bool) -> ZoneState`
- Produces: `parse_os_release(output: str) -> str`
- Produces: `parse_rich_rules(output: str) -> tuple[RichRule, ...]`
- Raises: `FirewallParseError(operation, reason)`

- [ ] **Step 1: Add representative firewalld 2.x fixtures and failing parser tests**

```python
from pathlib import Path

from app.firewalld.parser import parse_active_zones, parse_zone_state

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_active_zone_interface_blocks():
    output = "public\n  interfaces: eth0 eth1\ninternal\n  sources: 10.0.0.0/8\n"
    assert parse_active_zones(output) == {"public": ("eth0", "eth1"), "internal": ()}


def test_parses_zone_details_without_losing_port_ranges():
    output = (FIXTURES / "zone_public.txt").read_text(encoding="utf-8")
    zone = parse_zone_state("public", output, permanent=False)
    assert ("8000-8100", "tcp") in {(port.port, port.protocol) for port in zone.ports}
    assert zone.services == ("http", "https", "ssh")
    assert zone.masquerade is False
```

Cover whitespace, empty fields, multiple rich-rule lines, sources, protocols, forwarding, malformed lines, and `/etc/os-release` quoted values.

- [ ] **Step 2: Run parser tests and confirm failure**

Run: `python -m pytest tests/firewalld/test_parser.py -v`

Expected: FAIL because parser functions are missing.

- [ ] **Step 3: Implement pure line-oriented parsers**

Split zone fields only on the first colon. Normalize booleans from `yes`/`no`; split list fields on whitespace; validate every parsed port and protocol; preserve each rich-rule line as a structured display model without reinterpreting it as a command. Reject missing required fields with `FirewallParseError` naming the logical operation but not dumping unlimited output.

- [ ] **Step 4: Run parser tests**

Run: `python -m pytest tests/firewalld/test_parser.py -v`

Expected: PASS for fixtures and malformed-output cases.

- [ ] **Step 5: Commit output parsing**

```bash
git add app/firewalld/parser.py app/utils/errors.py tests/firewalld
git commit -m "feat: parse firewalld state into typed models"
```

### Task 5: Firewalld service reads and connection test

**Files:**
- Create: `app/firewalld/service.py`
- Create: `tests/firewalld/fakes.py`
- Create: `tests/firewalld/test_service_reads.py`

**Interfaces:**
- Consumes executor protocol: `execute_command(spec: CommandSpec, sudo_password: str | None = None) -> CommandResult`
- Produces: `FirewalldService.detect() -> FirewalldInfo`
- Produces: `FirewalldService.connection_test() -> ConnectionTestResult`
- Produces: `FirewalldService.load_snapshot() -> FirewallSnapshot`
- Produces focused reads: `list_ports`, `list_services`, `list_available_services`, `list_zones`, `get_interfaces`, `list_rich_rules`

- [ ] **Step 1: Write failing detection and snapshot tests with a scripted executor**

```python
from app.firewalld.service import FirewalldService


def test_detection_distinguishes_missing_stopped_and_running(scripted_executor):
    scripted_executor.respond("get_state", exit_code=0, stdout="running\n")
    scripted_executor.respond("get_version", exit_code=0, stdout="2.3.1\n")
    info = FirewalldService(scripted_executor, "web01").detect()
    assert info.running
    assert info.version == "2.3.1"


def test_snapshot_loads_runtime_and_permanent_zones(scripted_executor, standard_firewalld_script):
    standard_firewalld_script.install(scripted_executor)
    snapshot = FirewalldService(scripted_executor, "web01").load_snapshot()
    assert snapshot.default_zone == "public"
    assert snapshot.runtime_zones[0].name == "public"
    assert snapshot.permanent_zones[0].permanent
```

Add exact cases for command-not-found, stopped daemon, permission denied, unsupported option, hostname, distribution, effective UID, and independent runtime/permanent reads.

- [ ] **Step 2: Run read-service tests and confirm failure**

Run: `python -m pytest tests/firewalld/test_service_reads.py -v`

Expected: FAIL because the service is missing.

- [ ] **Step 3: Implement injected execution, error classification, and snapshot assembly**

The service selects builders and parsers by logical operation. Classify common exit output into `FirewalldNotInstalledError`, `FirewalldNotRunningError`, `PermissionDeniedError`, `UnsupportedFirewalldFeatureError`, or `FirewallCommandError`. Keep classification strings centralized and tested.

`connection_test()` performs only fixed read probes and returns a tuple of named checks with pass/fail status and safe messages. It never modifies firewalld.

- [ ] **Step 4: Run read-service tests**

Run: `python -m pytest tests/firewalld/test_service_reads.py -v`

Expected: PASS with scripted executors and no network.

- [ ] **Step 5: Commit firewalld reads**

```bash
git add app/firewalld/service.py tests/firewalld/fakes.py tests/firewalld/test_service_reads.py
git commit -m "feat: inspect remote firewalld state safely"
```

### Task 6: Verified writes and partial results

**Files:**
- Modify: `app/firewalld/service.py`
- Create: `tests/firewalld/test_service_writes.py`

**Interfaces:**
- Produces: `add_port`, `remove_port`, `add_service`, `remove_service`, `set_default_zone`, `change_interface_zone`, `add_rich_rule`, `remove_rich_rule`, `reload_firewalld`
- Every write accepts `target: ApplyTarget` and `sudo_password: str | None = None`
- Every write returns `CompositeOperationResult`

- [ ] **Step 1: Write failing tests for order, verification, partial success, and no retry**

```python
from app.models.enums import ApplyTarget


def test_both_runs_permanent_before_runtime_and_verifies_each(service, scripted_executor):
    scripted_executor.install_successful_add_port("public", "8080", "tcp")
    result = service.add_port("public", "8080", "tcp", ApplyTarget.BOTH)
    assert scripted_executor.operations[:2] == ["add_port_permanent", "verify_port_permanent"]
    assert scripted_executor.operations[2:4] == ["add_port_runtime", "verify_port_runtime"]
    assert result.is_success


def test_runtime_success_and_permanent_failure_is_partial(service, scripted_executor):
    scripted_executor.install_partial_add_port_failure("public", "8080", "tcp")
    result = service.add_port("public", "8080", "tcp", ApplyTarget.BOTH)
    assert result.is_partial
    assert scripted_executor.count("add_port_permanent") == 1
    assert scripted_executor.count("add_port_runtime") == 1


def test_zero_exit_with_missing_refreshed_value_is_verification_failure(service, scripted_executor):
    scripted_executor.install_unverified_add_port("public", "8080", "tcp")
    result = service.add_port("public", "8080", "tcp", ApplyTarget.RUNTIME)
    assert not result.is_success
    assert result.runtime.verification_status.name == "FAILED"
```

Add corresponding add/remove tests for service and rich rule, default-zone change, interface assignment, reload refresh, supplied sudo-password forwarding, and failure without automatic rollback.

- [ ] **Step 2: Run write-service tests and confirm failure**

Run: `python -m pytest tests/firewalld/test_service_writes.py -v`

Expected: FAIL because write methods are missing.

- [ ] **Step 3: Implement a shared permanent-first target runner and resource-specific verifiers**

Create a private `_apply_targets(operation, target, build, verify, sudo_password)` that expands `BOTH` to permanent then runtime, executes each target once, verifies immediately by querying that target, and records independent `TargetResult` values. Catch domain errors per target so runtime still runs after a permanent failure. Do not catch programmer errors.

- [ ] **Step 4: Run write-service and full backend tests**

Run: `python -m pytest tests/firewalld/test_service_writes.py -v`

Expected: PASS for all resource writes and partial states.

Run: `python -m pytest tests/ssh tests/firewalld -v`

Expected: all backend tests PASS.

- [ ] **Step 5: Commit verified writes**

```bash
git add app/firewalld/service.py tests/firewalld/test_service_writes.py
git commit -m "feat: verify runtime and permanent firewall changes"
```

### Task 7: Conservative SSH lockout-risk analysis

**Files:**
- Create: `app/firewalld/lockout.py`
- Create: `tests/firewalld/test_lockout.py`

**Interfaces:**
- Produces: `LockoutRisk(level: RiskLevel, reasons: tuple[str, ...])`
- Produces: `assess_lockout_risk(change: FirewallChange, snapshot: FirewallSnapshot, ssh_port: int) -> LockoutRisk`
- Produces: typed changes `RemovePortChange`, `RemoveServiceChange`, `MoveInterfaceChange`, `RemoveRichRuleChange`

- [ ] **Step 1: Write failing risk tests**

```python
from app.firewalld.lockout import RemovePortChange, RemoveServiceChange, assess_lockout_risk


def test_removing_management_port_is_high_risk(snapshot):
    risk = assess_lockout_risk(RemovePortChange("public", "2222", "tcp"), snapshot, ssh_port=2222)
    assert risk.is_high
    assert "TCP port 2222" in risk.reasons[0]


def test_removing_ssh_service_is_high_risk(snapshot):
    assert assess_lockout_risk(RemoveServiceChange("public", "ssh"), snapshot, 22).is_high


def test_unrelated_udp_port_has_no_known_risk(snapshot):
    assert not assess_lockout_risk(RemovePortChange("public", "53", "udp"), snapshot, 22).has_risk
```

Add tests for port ranges containing the management port, active-interface movement, rich rules permitting the SSH port or service, and wording that says detection is incomplete.

- [ ] **Step 2: Run risk tests and confirm failure**

Run: `python -m pytest tests/firewalld/test_lockout.py -v`

Expected: FAIL because the risk module is missing.

- [ ] **Step 3: Implement pure conservative analysis**

Match TCP only for management ports, treat an encompassing range as risk, compare interface assignments against active zones, and inspect only structured rich-rule fields. Never classify a change as guaranteed safe; return no known risk or one or more warning reasons.

- [ ] **Step 4: Run risk and complete backend tests**

Run: `python -m pytest tests/firewalld/test_lockout.py -v`

Expected: PASS.

Run: `python -m pytest -v`

Expected: all foundation and backend tests PASS offline.

- [ ] **Step 5: Commit lockout analysis**

```bash
git add app/firewalld/lockout.py tests/firewalld/test_lockout.py
git commit -m "feat: warn about SSH lockout-sensitive changes"
```

## Plan 2 Completion Check

Run: `python -m pytest -v`

Expected: all tests pass with no network. Inspect logs captured by tests and confirm fixture SSH and sudo passwords do not appear. Confirm `git status --short` is empty before beginning the session and Ports GUI plan.
