# Remote firewalld Manager Design

Date: 2026-08-28

## Purpose

Remote firewalld Manager is a Python desktop application for safely administering `firewalld` on multiple remote Linux servers over SSH. It replaces repetitive manual SSH and `firewall-cmd` work with a constrained, responsive, auditable GUI. The first release prioritizes correctness, lockout protection, isolated server state, and explicit verification over breadth or automation.

The desktop client is tested primarily on Windows and remains portable through Python 3.11+, PySide6, Paramiko, and PyYAML. Remote compatibility targets modern `firewalld` 2.x releases.

## Confirmed Product Decisions

- Work is delivered incrementally on the repository's `main` branch.
- Portable application data is resolved relative to the directory containing `main.py`, not the process working directory.
- `config.yaml`, `known_hosts`, and `logs/` live beside `main.py`.
- The SSH login password is the only password persisted locally, in plaintext YAML as required by the product specification.
- Sudo passwords are never persisted. They are prompted for when required and retained only in the affected server's in-memory session until disconnect.
- SSH trust uses the application's own `known_hosts` file.
- Operations for one server are serialized. Different servers may run concurrently.
- Rich rules use structured fields only in the MVP. The optional free-form editor is excluded.
- The optional dashboard and charts are excluded from the MVP.
- The Ports tab is a table-based primary workflow.

## Scope

The MVP supports multiple YAML server profiles, password-based SSH, explicit host-key trust, root and sudo-enabled users, connection testing, firewalld detection, runtime and permanent state, zones, ports and ranges, services, interfaces, structured rich rules, firewalld reload, confirmations, lockout warnings, background work, logs, typed errors, and automated tests.

It does not provide a terminal, arbitrary remote commands, file browsing, package installation, direct iptables or nftables editing, SELinux or user administration, container or cloud firewall management, bulk changes, or a multi-user web service.

## Architecture

Dependencies flow downward through six layers:

```text
PySide6 GUI
    -> Controllers
    -> Per-server operation scheduler
    -> Firewalld service
    -> Allowlisted command builder and parsers
    -> Per-server Paramiko SSH manager
```

### Bootstrap and portable paths

`main.py` determines the directory containing itself, initializes portable paths, configures logging, loads configuration, creates controllers, and starts Qt. Runtime behavior does not depend on the shell's current directory.

### Configuration

`ConfigManager` loads `config.yaml` and creates typed application and server models. It validates required fields, unique IDs, port and timeout ranges, and supported keys. The application does not rewrite the file.

Server profiles contain the required identity and SSH fields plus optional port, sudo flag, and timeouts. A sudo-password field is unsupported because sudo credentials must not be persisted.

Configuration reload is transactional. An invalid new file leaves the working configuration and sessions intact. Unchanged profiles retain their sessions; changed and removed profiles disconnect; new profiles appear disconnected.

### Per-server sessions

`ServerController` owns a `ServerSession` for every configured server. A session contains exactly one SSH manager, connection status, immutable firewall snapshot, per-server logs, latest error, operation state, sudo credential reference, and generation identifier. Connections, state, and credentials never cross server boundaries.

Disconnect, changed configuration, failed sudo authentication, and application shutdown clear the session's sudo credential reference. Python cannot guarantee physical memory zeroization, so documentation describes the behavior accurately as memory-only until disconnect.

### Background scheduling

`OperationScheduler` uses `QThreadPool`, `QRunnable`, and Qt signals. It serializes jobs by server ID while permitting jobs for different servers to run concurrently. Paramiko clients are never used concurrently within a server session.

Workers return typed values and errors. Only the GUI thread touches widgets. Every job carries the session generation; stale results from a disconnected or replaced session are discarded.

### Command construction and execution

`FirewalldCommandBuilder` exposes only approved logical operations. It returns a typed command specification containing an operation name and argument tuple. Values are centrally validated against strict syntax and, where applicable, the current inventory returned by the server.

A single renderer safely quotes each argument before passing the command string to Paramiko. Neither widgets nor controllers accept or construct arbitrary shell text. Structured rich-rule inputs are converted to an allowlisted rule grammar.

`FirewalldService` executes command specifications, parses results, coordinates runtime and permanent targets, refreshes state, and verifies writes. It can be tested independently from Qt and Paramiko through injected executors.

### Controllers and GUI

Controllers translate user actions into validation, risk analysis, confirmation previews, scheduled operations, and view-ready results. GUI widgets gather input and render state without knowing SSH or command syntax.

The main window contains a server sidebar, selected-server header, status bar, and Overview, Ports, Services, Zones, Interfaces, Rich Rules, and Logs tabs. Management surfaces use `QTableView` with dedicated models and proxy filtering where useful.

## SSH and Host-Key Security

Each server receives its own Paramiko client. A known matching host key connects normally. An unknown key stops the attempt and returns the host, algorithm, and SHA-256 fingerprint to the GUI. After explicit confirmation, the key is written atomically to the application `known_hosts` file and the connection is retried.

A changed known key is rejected with a high-severity warning. The application does not offer one-click replacement. Reloading configuration does not clear trusted keys.

Expected authentication, DNS, refusal, timeout, disconnect, and key errors become typed domain errors. Authentication exceptions and configuration objects are not logged.

## Sudo Design

Root users run approved commands directly. For a profile with `sudo: true`, the service first attempts `sudo -n -- <approved command>`.

When sudo reports that authentication is required, the worker returns a typed authentication-required result. The GUI displays a masked password dialog and resubmits the operation using `sudo -S -p "" -- <approved command>`. The password is sent only through the SSH channel's standard input. It never appears in an argument, log, exception, audit record, status message, or file.

The password is cached only in that server's live in-memory session. Incorrect authentication clears it and allows a deliberate retry. No automatic password guessing or SSH-password reuse occurs.

## State and Data Flow

Selecting a server does not connect automatically. A connection request performs SSH authentication, any required host-key decision, firewalld and privilege checks, an initial summary refresh, and publication of a new immutable snapshot.

Detailed tabs can load their data on first use. Read operations replace complete typed snapshots. A failed read preserves the last snapshot but marks it stale.

All modifications follow this pipeline:

```text
Validate against current remote inventory
-> determine selected server and target
-> calculate lockout risk
-> show exact change preview
-> receive explicit confirmation
-> enqueue for that server
-> execute requested target or targets
-> query runtime and/or permanent state
-> verify expected state
-> publish updated snapshot and audit result
```

For Runtime + Permanent, the permanent command runs first and the runtime command second. This maximizes the chance that both commands complete before a runtime change can terminate the management connection. Execution and verification are tracked independently for both targets. Partial success is explicit and is not automatically rolled back or followed by a reload.

## Firewall Operations

The allowlisted backend covers state and version detection, available and active zones, default-zone read and change, zone details, ports, services, interfaces, structured rich rules, and firewalld reload. Runtime and permanent reads are separate.

Ports support TCP and UDP, single values from 1 through 65535, and ascending ranges within the same bounds. Zone, service, and interface values must be drawn from the current remote inventory. Structured rich rules support validated source, destination, service or port, protocol, and action fields; supported actions are accept, reject, and drop.

Reload requires confirmation, warns that runtime-only changes can disappear, and refreshes state afterward. Permanent changes do not trigger automatic reload.

## Lockout Protection

Risk analysis runs before confirmation and produces conservative warnings for removal of the configured SSH TCP port, removal of the `ssh` service, movement of a management interface, and removal of a structured rule that appears to permit management traffic.

Warnings identify the server and management port, explain the possibility of losing access, state that detection is incomplete, and require an explicit Apply Anyway action. The protection warns rather than claims to prove safety.

## GUI Behavior

The server sidebar shows name, host, and a text-plus-icon state indicator. The main area shows the selected server and tabbed management views. No server connects on startup.

Controls associated with an active operation are disabled for that server while other servers remain usable. Loading, empty, disconnected, stale, unsupported, and failed states are visually distinct and do not rely on color alone.

Confirmation dialogs display server, host, logical operation, target zone, exact resource, and runtime/permanent scope. Host-key, sudo-password, configuration, partial-result, and high-risk confirmation dialogs are typed and purpose-specific. Destructive actions require a selected row and repeat the exact resource being removed.

Ports show Port, Protocol, Zone, Runtime, and Permanent columns, plus zone filtering, view filtering, search, refresh, add, and remove actions. Services, interfaces, and rich rules use table-based selection. Zones show detailed runtime or permanent state. The Logs tab supports clear view, copy, and refresh; clearing the view does not delete log files.

Standard PySide6 controls, scalable layouts, keyboard navigation, masked password input, and platform styling provide Windows-first usability without Windows-only application logic.

## Error Handling and Recovery

Typed errors cover configuration, SSH authentication, connection, host keys, command timeout, sudo authentication, permission, missing or stopped firewalld, unsupported operations, invalid firewall arguments, remote command failure, parsing, and post-write verification.

Write operations are never retried automatically. Read failures allow manual refresh. Remote disconnect invalidates the affected session state and requires reconnect. A timed-out command closes its channel and checks whether the SSH session remains usable.

A zero exit code followed by failed verification is reported as command accepted but verification failed. Runtime/permanent composite results distinguish complete success, complete failure, and partial success. Parser failures affect only the relevant data area and do not crash unrelated tabs.

## Logging

The application uses a rotating log file under `logs/` and sanitized per-server in-memory entries for the Logs tab. Entries record timestamp, severity, server ID, logical operation, validated target, duration, and outcome.

Configured secrets, password-like fields, raw configuration objects, and authentication exception contents are forbidden. A centralized redaction filter provides defense in depth. Log copying returns only sanitized display entries.

## Testing Strategy

Implementation is test-driven. `pytest` covers configuration, validators, paths, command building and rendering, parsers, SSH and sudo behavior, service orchestration, verification, scheduling, session isolation, controllers, and Qt models and dialogs. `pytest-qt` provides focused GUI tests.

SSH executors and Paramiko channels are injected or mocked. Tests cover unknown and changed host keys, authentication failure, connection and command timeouts, remote disconnect, sudo prompts and failures, injection-shaped input, partial runtime/permanent results, stale generations, same-server serialization, and cross-server concurrency.

Normal tests require no network or production server. An explicitly opt-in live suite may use disposable hosts. The documented manual acceptance flow uses at least three disposable profiles and exercises independent state, port and service changes, zones, interfaces, rich rules, partial failure, reconnects, readable errors, credential redaction, and SSH lockout warnings.

Windows is the primary automated and manual client platform. The implementation supports Python 3.11 and newer supported versions.

## Delivery Sequence

1. Portable paths, configuration, validation, logging safeguards, and domain models.
2. Paramiko sessions, host-key trust, execution, timeouts, sudo, and mocked tests.
3. Command builder, renderer, parsers, service operations, composite results, and verification.
4. Per-server sessions, controllers, and keyed scheduling.
5. Main window, sidebar, Overview, connection testing, and status behavior.
6. Complete Ports workflow.
7. Services, Zones, default zone, Interfaces, and structured Rich Rules.
8. Reload, warnings, Logs, error dialogs, documentation, acceptance checks, and security review.

Each phase delivers passing tests before the next phase connects to it. The backend is complete and independently testable before GUI integration.

## Definition of Done

The MVP is complete when all automated tests pass from a clean environment; the application starts on Windows; three server profiles remain isolated; the UI remains responsive; host-key decisions are explicit; persisted and in-memory credentials are handled as designed; all required firewall resources can be read and modified within scope; runtime and permanent outcomes are separate and verified; dangerous changes require confirmation and lockout warnings; state refreshes after writes; and the README documents installation, portable configuration, SSH trust, sudo behavior, testing, and troubleshooting.
