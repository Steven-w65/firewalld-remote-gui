# Remote firewalld Manager

Remote firewalld Manager is a constrained desktop GUI for administering
`firewalld` 2.x on multiple remote Linux servers over SSH. It provides
inventory-backed views and confirmed, verified changes for zones, ports,
services, interfaces, structured rich rules, and firewalld reloads. Servers are
kept isolated from one another, and selecting a server never connects it
automatically.

The client is developed and tested primarily on Windows. It uses portable
Python and Qt code and can also run on Linux and macOS. Python 3.11 or newer is
required.

## Screenshots

Reserved for screenshots of the Windows desktop application.

## Install

Clone or copy the repository to the folder where you want to keep the portable
application. All commands below run from that folder.

### Windows (primary platform)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item config.example.yaml config.yaml
python main.py
```

If PowerShell activation is disabled by local policy, activation is optional:
run `.\.venv\Scripts\python.exe` in place of `python` in the remaining commands.

### Linux and macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp config.example.yaml config.yaml
python main.py
```

The application does not install, start, or reconfigure SSH or firewalld on a
remote host. Prepare those services separately before connecting.

## Portable files

Portable paths are always resolved from the directory containing the executing
`main.py`, not from the shell's current directory, the user profile, AppData,
the registry, or a platform configuration directory.

| Path beside `main.py` | Purpose |
| --- | --- |
| `config.yaml` | Server profiles and application settings. This file can contain plaintext SSH passwords. |
| `known_hosts` | SSH host keys explicitly trusted through this application. |
| `logs/` | Sanitized rotating application log files. |

`known_hosts` temporary files may briefly exist while a trust update is written
atomically. These portable state files are intentionally ignored by Git.

## Configuration

Copy `config.example.yaml` to `config.yaml`, then edit the copy. YAML field names
are strict: unknown fields, invalid types, duplicate server IDs, and unsupported
password fields such as `sudo_password` prevent startup. Quote passwords when
they contain YAML punctuation.

The optional top-level `application` mapping supports:

| Field | Type and default | Meaning |
| --- | --- | --- |
| `ssh_timeout` | positive number, `10.0` | Default SSH connect, authentication, and banner timeout in seconds. |
| `command_timeout` | positive number, `20.0` | Default timeout in seconds for an approved remote operation. |
| `confirm_changes` | boolean, `true` | Compatibility setting retained by the configuration schema. The MVP still requires explicit confirmation for every firewall mutation; keep this `true`. |
| `strict_host_key_checking` | boolean, `true` | Compatibility setting retained by the configuration schema. The MVP always enforces the application-owned host-key trust workflow; keep this `true`. |

The required top-level `servers` list contains one mapping per server:

| Field | Required | Type and default | Meaning |
| --- | --- | --- | --- |
| `id` | yes | non-empty string | Unique stable profile ID used to isolate work and logs. |
| `name` | yes | non-empty string | Human-readable server name. |
| `host` | yes | non-empty string | DNS name or IP address accepted by the SSH client. |
| `username` | yes | non-empty string | Remote SSH login user. |
| `password` | yes | non-empty string | Plaintext SSH login password. This is the only locally persisted password. |
| `port` | no | integer `22` | SSH port from 1 through 65535. |
| `sudo` | no | boolean `false` | Whether approved privileged commands may use sudo for a non-root user. |
| `connect_timeout` | no | positive number | Per-server override for `application.ssh_timeout`. |
| `command_timeout` | no | positive number | Per-server override for `application.command_timeout`. |

The application reads but does not rewrite `config.yaml`. Reloading configuration
is transactional: an invalid replacement does not replace working profiles or
sessions. Changed and removed profiles are disconnected; unchanged profiles keep
their sessions.

## Credential and command security

The SSH password in each profile is stored locally as plaintext in
`config.yaml`. Anyone or any process that can read that file can recover it,
including another non-administrator account if filesystem permissions allow
that account to read the application folder. Restrict access to the portable
folder and use dedicated, least-privilege SSH accounts. Do not commit or share
`config.yaml`.

Sudo passwords are never configuration fields and are never written to disk.
When needed, the GUI asks through a masked dialog and retains the password only
in the selected server's live in-memory session until disconnect. It is also
dropped when that session is replaced or authentication fails. Python cannot
guarantee physical memory zeroization, so "memory-only" does not mean that every
copy can be securely overwritten in RAM.

Privileged execution follows these modes:

- A profile whose `username` is `root` runs approved operations directly and
  does not ask for a sudo password.
- A non-root profile with `sudo: false` also runs directly. If that account
  lacks permission, the operation fails with a permission error.
- A non-root profile with `sudo: true` first tries non-interactive,
  passwordless sudo. If sudo requires authentication, the GUI prompts and sends
  the password only through SSH standard input for an approved operation.

For passwordless operation, edit sudo policy with `visudo`. Scope the rule to
the dedicated account, the root run-as identity, the distribution's exact
`firewall-cmd` path, and only the argument forms the operator needs. Do not grant
`ALL`, a shell, an interpreter, or package-management commands. Validate the
result on a disposable host with `sudo -l`; sudoers syntax and the
`firewall-cmd` path vary by distribution. A password-prompt setup can be safer
than an overly broad `NOPASSWD` rule.

The application offers no terminal, arbitrary command field, generic command
execution entry point, package installation, or free-form rich-rule editor.
Controllers and widgets can invoke only typed, allowlisted operations.

## SSH host-key trust

SSH trust is separate from the user's or system's OpenSSH files. The application
loads only the `known_hosts` file beside `main.py`.

On first contact with an unknown key, connection stops and the GUI shows the
host, key algorithm, and SHA-256 fingerprint. Verify that fingerprint through an
independent trusted channel before accepting it. Acceptance writes the key to
the app-local file and retries the connection.

A changed known key is blocked and cannot be replaced with one click. First
verify the server and new fingerprint independently and investigate a possible
man-in-the-middle attack. To recover deliberately, close the application, back
up `known_hosts`, and manually edit or remove only the affected host entry
(`host` for SSH port 22 or `[host]:port` for a nonstandard port). Reconnect and
accept the verified key as a new trust decision. Deleting the entire file
discards trust for every server and is not recommended.

## Use

Start the GUI from the repository directory or any other working directory:

```powershell
python main.py
```

Select a profile and choose **Connect**. Startup and selection alone never open
an SSH connection. Firewall changes follow a fixed flow: validate against the
current remote inventory, show the exact Runtime, Permanent, or Runtime +
Permanent preview, require confirmation, execute once per requested target,
verify each target, and refresh the snapshot. Runtime + Permanent runs the
permanent target first. Partial results are reported and are not rolled back.
Permanent changes never cause an automatic reload.

High-risk confirmations warn before removing likely SSH access or moving an
active interface. The warning is conservative; it cannot prove that a change is
safe. A firewalld reload also requires confirmation because runtime-only changes
may disappear.

## Logs

Sanitized file logs are written to
`logs/remote-firewalld-manager.log` beside `main.py`. The file rotates at 2 MiB
and keeps up to five backups. The Logs tab displays only the selected server's
sanitized in-memory entries. **Clear View** does not delete or alter the rotating
files; **Refresh** rereads the in-memory buffer; **Copy** copies only visible
sanitized text.

Raw configuration objects, authentication exception contents, and configured
secrets are forbidden from logs, but redaction is defense in depth rather than a
reason to publish logs without inspection. Review a log before sharing it.

## Connection statuses and troubleshooting

| Status | Meaning and action |
| --- | --- |
| **Disconnected** | No live session exists. Select the profile and choose **Connect** when ready. |
| **Connecting** | SSH authentication and remote firewalld checks are in progress. Wait for the configured timeout; repeated timeouts usually indicate host, port, routing, firewall, or SSH-service problems. |
| **Connected** | SSH and the initial firewalld snapshot succeeded. Management actions are available unless another operation for this server is busy. |
| **Authentication failed** | The SSH server rejected `username` or `password`. Correct the plaintext profile values, reload configuration, and reconnect. The application does not reuse the SSH password as a sudo password. |
| **Connection error** | DNS, routing, refusal, timeout, disconnect, SSH protocol, or remote probe failure prevented a usable session. Check `host`, `port`, network reachability, the SSH service, timeouts, and the sanitized log, then reconnect. |
| **Host key error** | An unknown key needs independently verified confirmation, a saved key changed, or the app-local trust store could not be read safely. Never accept an unverified fingerprint; use the deliberate manual recovery procedure above for changed keys. |
| **Permission denied** | The account or sudo policy cannot perform an approved operation, or a prompted sudo password was rejected. Check `username`, `sudo`, `sudo -l`, and least-privilege sudoers policy. Restart the operation to deliberately retry a rejected sudo password. |
| **firewalld not installed** | `firewall-cmd` was not found. Install a supported firewalld 2.x release manually through the host's normal administration process; this application cannot install packages. |
| **firewalld not running** | firewalld is installed but stopped. Inspect and start the service through a separate trusted administration path, then reconnect; the application does not start services. |

If startup displays a configuration error, confirm that `config.yaml` is beside
the executing `main.py`, is readable UTF-8 YAML, contains a `servers` list, and
uses only the fields documented above. Startup errors use fixed text and do not
echo YAML, exception strings, paths, or credentials. If a previously loaded
snapshot is marked stale, refresh or reconnect before making another change.

## Test

The automated suite is offline: injected SSH and service adapters avoid network
connections and production hosts.

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
python -m pytest -v
```

On Linux or macOS:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -v
```

Live checks are optional and must use disposable hosts. Firewall changes can
remove remote access. Use hosts with backups or independent console access,
record their current rules first, and never run exploratory or acceptance
changes against production systems.
