# Foundation and Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the portable Python project, typed configuration and domain models, centralized validation, and credential-safe logging.

**Architecture:** `main.py` delegates portable path resolution and configuration loading to focused modules. Frozen dataclasses carry configuration and firewall state, while pure validation functions and a redacting log filter provide reusable security boundaries for every later layer.

**Tech Stack:** Python 3.11+, PySide6, Paramiko, PyYAML, pytest, pytest-qt

**Spec:** `docs/superpowers/specs/2026-08-28-remote-firewalld-manager-design.md`

## Global Constraints

- Python 3.11 or newer with type hints throughout.
- Windows is the primary tested client platform; application code remains portable.
- Resolve portable data relative to the directory containing `main.py`, never the process working directory.
- Persist only the SSH login password; never persist a sudo password.
- Never log credentials or complete configuration objects.
- Keep GUI, controllers, SSH, command building, parsing, and models in separate modules.
- Use `pytest`; normal tests require no network or production server.
- Work directly on `main` and keep each task in a focused commit.

---

## File Map

- `main.py`: application entry point; initially delegates to a bootstrap stub.
- `requirements.txt`: pinned-compatible runtime and test dependencies.
- `pytest.ini`: deterministic test discovery and Qt test settings.
- `app/paths.py`: immutable portable path model and resolution.
- `app/config/models.py`: `ApplicationConfig`, `ServerConfig`, and `LoadedConfig`.
- `app/config/config_manager.py`: transactional YAML loading and reload comparison.
- `app/models/enums.py`: shared connection, target, and operation-status enums.
- `app/models/command.py`: trusted command and result value objects.
- `app/models/firewall.py`: typed firewall resource and snapshot models.
- `app/utils/errors.py`: safe domain exception hierarchy.
- `app/utils/validation.py`: pure syntax and inventory validation.
- `app/utils/logging_setup.py`: redaction and rotating logging.

### Task 1: Portable project bootstrap

**Files:**
- Create: `main.py`
- Create: `requirements.txt`
- Create: `pytest.ini`
- Create: `app/__init__.py`
- Create: `app/paths.py`
- Create: `tests/test_paths.py`

**Interfaces:**
- Produces: `PortablePaths.from_entrypoint(entrypoint: Path) -> PortablePaths`
- Produces fields: `root`, `config_file`, `known_hosts_file`, `log_dir`, all `Path`
- Produces: `main.main() -> int`

- [ ] **Step 1: Write the failing portable-path tests**

```python
from pathlib import Path

from app.paths import PortablePaths


def test_paths_are_anchored_to_main_file_not_cwd(tmp_path, monkeypatch):
    app_dir = tmp_path / "portable"
    entrypoint = app_dir / "main.py"
    elsewhere = tmp_path / "elsewhere"
    app_dir.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    paths = PortablePaths.from_entrypoint(entrypoint)

    assert paths.root == app_dir.resolve()
    assert paths.config_file == app_dir.resolve() / "config.yaml"
    assert paths.known_hosts_file == app_dir.resolve() / "known_hosts"
    assert paths.log_dir == app_dir.resolve() / "logs"
```

- [ ] **Step 2: Run the test and confirm the missing module failure**

Run: `python -m pytest tests/test_paths.py -v`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'app.paths'`.

- [ ] **Step 3: Implement the immutable portable path model and minimal entry point**

```python
# app/paths.py
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PortablePaths:
    root: Path
    config_file: Path
    known_hosts_file: Path
    log_dir: Path

    @classmethod
    def from_entrypoint(cls, entrypoint: Path) -> "PortablePaths":
        root = entrypoint.resolve().parent
        return cls(
            root=root,
            config_file=root / "config.yaml",
            known_hosts_file=root / "known_hosts",
            log_dir=root / "logs",
        )
```

Create package marker files, set `main.main()` to return `0`, declare `PySide6`, `paramiko`, `PyYAML`, `pytest`, and `pytest-qt` in `requirements.txt`, and configure `testpaths = tests` in `pytest.ini`.

- [ ] **Step 4: Run the focused test and import smoke test**

Run: `python -m pytest tests/test_paths.py -v`

Expected: PASS.

Run: `python -c "import app; import main; raise SystemExit(main.main())"`

Expected: exit code 0 with no output.

- [ ] **Step 5: Commit the bootstrap**

```bash
git add main.py requirements.txt pytest.ini app/__init__.py app/paths.py tests/test_paths.py
git commit -m "build: add portable Python project foundation"
```

### Task 2: Typed configuration and transactional loading

**Files:**
- Create: `app/config/__init__.py`
- Create: `app/config/models.py`
- Create: `app/config/config_manager.py`
- Create: `app/utils/__init__.py`
- Create: `app/utils/errors.py`
- Create: `config.example.yaml`
- Create: `tests/test_config.py`

**Interfaces:**
- Consumes: `PortablePaths.config_file`
- Produces: `ServerConfig(id, name, host, username, password, port=22, sudo=False, connect_timeout=None, command_timeout=None)`
- Produces: `ApplicationConfig(ssh_timeout=10.0, command_timeout=20.0, confirm_changes=True, strict_host_key_checking=True)`
- Produces: `LoadedConfig(application: ApplicationConfig, servers: tuple[ServerConfig, ...])`
- Produces: `ConfigManager.load() -> LoadedConfig`
- Produces: `ConfigManager.diff(old: LoadedConfig, new: LoadedConfig) -> ConfigDiff`

- [ ] **Step 1: Write failing tests for valid, invalid, and duplicate configurations**

```python
import pytest

from app.config.config_manager import ConfigManager
from app.utils.errors import ConfigurationError


def test_loads_multiple_servers_with_defaults(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "servers:\n"
        "  - id: web01\n    name: Web\n    host: 192.0.2.10\n"
        "    username: admin\n    password: secret\n"
        "  - id: db01\n    name: DB\n    host: db.example\n"
        "    username: root\n    password: other\n    port: 2222\n",
        encoding="utf-8",
    )

    loaded = ConfigManager(path).load()

    assert [server.id for server in loaded.servers] == ["web01", "db01"]
    assert loaded.servers[0].port == 22
    assert loaded.servers[1].port == 2222


@pytest.mark.parametrize(
    "body, message",
    [
        ("servers: [{id: web01}]", "missing required field"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p, port: 0}]", "port"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p, sudo_password: x}]", "sudo_password"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p}, {id: a, name: B, host: h2, username: u, password: p}]", "duplicate server id"),
    ],
)
def test_rejects_invalid_configuration(tmp_path, body, message):
    path = tmp_path / "config.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ConfigurationError, match=message):
        ConfigManager(path).load()
```

Add a diff test asserting that unchanged, changed, added, and removed server IDs are classified separately.

- [ ] **Step 2: Run the configuration tests and confirm failure**

Run: `python -m pytest tests/test_config.py -v`

Expected: FAIL because the configuration package does not exist.

- [ ] **Step 3: Implement frozen configuration models and strict YAML conversion**

Use `yaml.safe_load`, require the root to be a mapping, require `servers` to be a list, reject unknown server and application keys, reject booleans where integer ports are expected, and raise `ConfigurationError` with paths such as `servers[1].port`. Never include field values in an exception.

```python
@dataclass(frozen=True, slots=True)
class ServerConfig:
    id: str
    name: str
    host: str
    username: str
    password: str = field(repr=False)
    port: int = 22
    sudo: bool = False
    connect_timeout: float | None = None
    command_timeout: float | None = None
```

Implement `ConfigDiff(unchanged, changed, added, removed)` as tuples of IDs. Equality of frozen `ServerConfig` values determines whether a profile changed.

- [ ] **Step 4: Add a portable example configuration without real secrets**

Create `config.example.yaml` with application defaults and three documentation-only servers using RFC 5737 addresses and `change-me` passwords. Include `sudo: true` but no sudo-password field.

- [ ] **Step 5: Run the focused tests**

Run: `python -m pytest tests/test_config.py -v`

Expected: PASS for valid YAML, missing fields, unknown fields, duplicate IDs, invalid ports, timeouts, sudo flags, and diff classification.

- [ ] **Step 6: Commit configuration support**

```bash
git add app/config app/utils config.example.yaml tests/test_config.py
git commit -m "feat: add typed portable server configuration"
```

### Task 3: Shared operation and firewall models

**Files:**
- Create: `app/models/__init__.py`
- Create: `app/models/enums.py`
- Create: `app/models/command.py`
- Create: `app/models/firewall.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Produces: `ConnectionStatus`, `ApplyTarget`, `TargetStatus`
- Produces: `CommandSpec(operation: str, argv: tuple[str, ...], requires_privilege: bool = True)`
- Produces: `CommandResult(success, exit_code, stdout, stderr, server_id, operation, duration_seconds)`
- Produces: `TargetResult(target, execution_status, verification_status, result, message)`
- Produces: `CompositeOperationResult(operation, runtime, permanent)`
- Produces: `FirewallPort`, `ZoneState`, `InterfaceAssignment`, `RichRule`, `FirewallSnapshot`
- `FirewallSnapshot.runtime_zones` and `.permanent_zones` are `tuple[ZoneState, ...]`
- Produces: `FirewallSnapshot.zone(name: str, permanent: bool) -> ZoneState | None`
- Produces: `FirewallSnapshot.has_port(zone: str, port: str, protocol: str, permanent: bool) -> bool`

- [ ] **Step 1: Write failing value-object tests**

```python
from app.models.command import CommandResult, CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, TargetStatus
from app.models.firewall import FirewallPort


def test_composite_result_reports_partial_success():
    ok = CommandResult(True, 0, "success", "", "web01", "add_port", 0.2)
    runtime = TargetResult(ApplyTarget.RUNTIME, TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED, ok, "")
    permanent = TargetResult(ApplyTarget.PERMANENT, TargetStatus.FAILED, TargetStatus.NOT_RUN, None, "denied")

    result = CompositeOperationResult("add_port", runtime=runtime, permanent=permanent)

    assert result.is_partial
    assert not result.is_success


def test_firewall_port_normalizes_protocol():
    assert FirewallPort("8080", "TCP", "public", True, False).protocol == "tcp"
```

- [ ] **Step 2: Run and observe missing model failures**

Run: `python -m pytest tests/test_models.py -v`

Expected: FAIL during import.

- [ ] **Step 3: Implement immutable enums and dataclasses**

Define connection states exactly as disconnected, connecting, connected, authentication failed, connection error, host key error, permission error, firewalld not installed, and firewalld not running. `ApplyTarget` contains `RUNTIME`, `PERMANENT`, and `BOTH`; `TargetStatus` contains `NOT_RUN`, `SUCCEEDED`, `FAILED`, and `UNVERIFIED`.

`FirewallSnapshot` includes remote hostname, distribution, firewalld state/version, default zone, runtime zones, permanent zones, available services, and a `stale` flag. Use tuples and frozen dataclasses so workers publish complete snapshots. Add pure `zone()` and `has_port()` lookup helpers with the exact signatures above.

`RichRule` stores the exact remote rule string plus optional parsed structured fields. Existing rules that cannot be fully structured remain displayable and removable by their exact backend-returned value; only creation is limited to structured fields.

- [ ] **Step 4: Run model tests**

Run: `python -m pytest tests/test_models.py -v`

Expected: PASS, including complete success, complete failure, partial success, normalization, and immutability cases.

- [ ] **Step 5: Commit shared models**

```bash
git add app/models tests/test_models.py
git commit -m "feat: add immutable firewall operation models"
```

### Task 4: Centralized firewall input validation

**Files:**
- Create: `app/utils/validation.py`
- Create: `tests/test_validation.py`

**Interfaces:**
- Produces: `validate_port(value: str) -> str`
- Produces: `validate_protocol(value: str) -> str`
- Produces: `validate_inventory_value(kind: str, value: str, allowed: Collection[str]) -> str`
- Produces: `validate_ip_network(value: str) -> str`
- Produces: `validate_rich_action(value: str) -> str`
- Raises: `InvalidFirewallArgumentError(field: str, reason: str)` without including credentials

- [ ] **Step 1: Write failing validator tests**

```python
import pytest

from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_value, validate_port, validate_protocol


@pytest.mark.parametrize("value", ["22", "443", "8000-8100"])
def test_accepts_valid_ports(value):
    assert validate_port(value) == value


@pytest.mark.parametrize("value", ["0", "65536", "-1", "abc", "9000-8000", "22; rm -rf /"])
def test_rejects_invalid_ports(value):
    with pytest.raises(InvalidFirewallArgumentError):
        validate_port(value)


def test_inventory_value_must_come_from_remote_inventory():
    with pytest.raises(InvalidFirewallArgumentError, match="zone"):
        validate_inventory_value("zone", "public;id", {"public", "internal"})


def test_protocol_is_normalized_and_allowlisted():
    assert validate_protocol("TCP") == "tcp"
    with pytest.raises(InvalidFirewallArgumentError):
        validate_protocol("sctp")
```

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `python -m pytest tests/test_validation.py -v`

Expected: FAIL because validation functions are undefined.

- [ ] **Step 3: Implement strict pure validators**

Use a full-match regular expression for a single port or range, integer bounds of 1 through 65535, `ipaddress.ip_network(..., strict=False)` for address fields, and exact membership for inventory values. Return normalized strings. Never strip or reinterpret shell metacharacters into a valid value.

- [ ] **Step 4: Run validator tests**

Run: `python -m pytest tests/test_validation.py -v`

Expected: PASS for valid boundaries, invalid ranges, protocol case normalization, CIDR values, inventory membership, rich actions, whitespace, and injection-shaped values.

- [ ] **Step 5: Commit centralized validation**

```bash
git add app/utils/validation.py app/utils/errors.py tests/test_validation.py
git commit -m "feat: validate firewall inputs centrally"
```

### Task 5: Credential-safe rotating logging

**Files:**
- Create: `app/utils/logging_setup.py`
- Create: `tests/test_logging_setup.py`

**Interfaces:**
- Produces: `SecretRedactionFilter(secrets: Iterable[str])`
- Produces: `configure_logging(log_dir: Path, secrets: Iterable[str]) -> logging.Logger`
- Produces: `ServerLogBuffer.append(record: logging.LogRecord) -> None`
- Produces: `ServerLogBuffer.entries(server_id: str) -> tuple[str, ...]`
- Produces: `ServerLogBuffer.clear(server_id: str) -> None`

- [ ] **Step 1: Write failing redaction and rotation tests**

```python
import logging

from app.utils.logging_setup import SecretRedactionFilter, configure_logging


def test_filter_redacts_message_arguments_and_exception_text():
    record = logging.LogRecord("app", logging.ERROR, __file__, 1, "login %s", ("top-secret",), None)
    SecretRedactionFilter(["top-secret"]).filter(record)
    assert "top-secret" not in record.getMessage()
    assert "[REDACTED]" in record.getMessage()


def test_configure_logging_creates_file_inside_portable_log_dir(tmp_path):
    logger = configure_logging(tmp_path / "logs", ["secret"])
    logger.info("connected")
    for handler in logger.handlers:
        handler.flush()
    assert (tmp_path / "logs" / "remote-firewalld-manager.log").exists()
```

- [ ] **Step 2: Run logging tests and confirm failure**

Run: `python -m pytest tests/test_logging_setup.py -v`

Expected: FAIL during import.

- [ ] **Step 3: Implement redaction before formatting and bounded rotation**

Use `RotatingFileHandler` with a 2 MiB limit and five backups. Copy and sanitize `record.msg`, `record.args`, and rendered exception text without mutating configuration objects. Add defensive patterns for keys named `password`, `passphrase`, and `credential`. Format entries with timestamp, severity, logger, and message.

Implement `ServerLogBuffer` as a thread-safe bounded deque per server. Clearing a view empties only that deque and never deletes files.

- [ ] **Step 4: Run logging and full foundation tests**

Run: `python -m pytest tests/test_logging_setup.py -v`

Expected: PASS with no secret in captured records or files.

Run: `python -m pytest -v`

Expected: all foundation tests PASS.

- [ ] **Step 5: Commit safe logging**

```bash
git add app/utils/logging_setup.py tests/test_logging_setup.py
git commit -m "feat: add credential-safe rotating logs"
```

## Plan 1 Completion Check

Run: `python -m pytest -v`

Expected: all tests pass without network access. Confirm `git status --short` is empty before beginning the SSH and firewalld backend plan.
