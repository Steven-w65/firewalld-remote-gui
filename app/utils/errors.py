from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ssh.host_keys import HostKeyChallenge


class ConfigurationError(ValueError):
    """Raised when the portable configuration is invalid."""


class InvalidFirewallArgumentError(ValueError):
    """Raised when a firewall operation argument fails strict validation."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid {field}: {reason}")


class FirewallParseError(ValueError):
    """Raised when bounded, typed parsing of firewalld output cannot continue."""

    _SAFE_OPERATIONS = frozenset({"active zones", "os release", "rich rules", "word list", "zone state"})

    def __init__(self, operation: str, reason: str) -> None:
        self.operation = operation if operation in self._SAFE_OPERATIONS else "firewalld output"
        self.reason = reason[:120] if isinstance(reason, str) else "invalid output"
        super().__init__(f"Unable to parse firewalld {self.operation} output.")


class FirewallCommandError(RuntimeError):
    """Raised when an approved remote firewall read fails safely."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        super().__init__(
            f"Firewalld command '{operation}' failed for server '{server_id}'."
        )


class FirewalldNotInstalledError(FirewallCommandError):
    """Raised when the approved firewall executable is unavailable."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        RuntimeError.__init__(
            self, f"Firewalld is not installed on server '{server_id}'."
        )


class FirewalldNotRunningError(FirewallCommandError):
    """Raised when a read requires a running firewalld daemon."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        RuntimeError.__init__(
            self, f"Firewalld is not running on server '{server_id}'."
        )


class PermissionDeniedError(FirewallCommandError):
    """Raised when remote authorization denies an approved firewall read."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        RuntimeError.__init__(
            self,
            f"Permission was denied for firewalld operation '{operation}' "
            f"on server '{server_id}'.",
        )


class UnsupportedFirewalldFeatureError(FirewallCommandError):
    """Raised when the remote firewalld does not support an approved read."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        RuntimeError.__init__(
            self,
            f"Firewalld operation '{operation}' is unsupported on server '{server_id}'.",
        )


class SystemProbeError(RuntimeError):
    """Raised when an approved fixed system identity probe fails safely."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        super().__init__(
            f"System probe '{operation}' failed for server '{server_id}'."
        )


class HostKeyStoreError(RuntimeError):
    """Raised when the application trusted-host file cannot be handled safely."""

    def __init__(self) -> None:
        super().__init__("Unable to read or update trusted SSH host keys.")


class UnknownHostKeyError(RuntimeError):
    """Raised when a host key needs explicit user confirmation."""

    def __init__(self, challenge: HostKeyChallenge) -> None:
        self.challenge: HostKeyChallenge = challenge
        super().__init__(
            "SSH host key for "
            f"{challenge.host}:{challenge.port} requires explicit trust "
            f"({challenge.algorithm}, {challenge.fingerprint_sha256})."
        )


class ChangedHostKeyError(RuntimeError):
    """Raised when a known host presents a different key for the same algorithm."""

    def __init__(
        self,
        host: str,
        port: int,
        expected_fingerprint: str,
        actual_fingerprint: str,
    ) -> None:
        self.host = host
        self.port = port
        self.expected_fingerprint = expected_fingerprint
        self.actual_fingerprint = actual_fingerprint
        super().__init__(
            f"SSH host key changed for {host}:{port}: expected {expected_fingerprint}; "
            f"received {actual_fingerprint}."
        )


class InvalidHostTokenError(ValueError):
    """Raised before an unsafe raw host token reaches known-hosts handling."""

    def __init__(self) -> None:
        super().__init__("SSH host must be a nonempty raw ASCII host token.")


class SSHError(RuntimeError):
    """Base class for credential-free SSH execution failures."""


class SSHConnectionError(SSHError):
    """Raised when an SSH connection cannot be established or used."""

    def __init__(self, server_id: str, category: str = "connection failed") -> None:
        self.server_id = server_id
        super().__init__(f"SSH {category} for server '{server_id}'.")


class SSHAuthenticationError(SSHConnectionError):
    """Raised when SSH authentication fails."""

    def __init__(self, server_id: str) -> None:
        super().__init__(server_id, "authentication failed")


class SSHConnectionTimeoutError(SSHConnectionError):
    """Raised when establishing an SSH connection times out."""

    def __init__(self, server_id: str) -> None:
        super().__init__(server_id, "connection timed out")


class SSHRemoteEOFError(SSHError):
    """Raised when a remote command channel closes without an exit status."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        super().__init__(
            f"SSH remote channel closed unexpectedly for server '{server_id}' "
            f"during operation '{operation}'."
        )


class CommandTimeoutError(SSHError):
    """Raised when a remote command exceeds its monotonic deadline."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        super().__init__(
            f"SSH command timed out for server '{server_id}' during operation '{operation}'."
        )


class SudoAuthenticationRequiredError(SSHError):
    """Raised when sudo needs a password before a command can run."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        super().__init__(
            f"Sudo authentication is required for server '{server_id}' "
            f"during operation '{operation}'."
        )


class SudoAuthenticationError(SudoAuthenticationRequiredError):
    """Raised when a supplied sudo password is rejected."""

    def __init__(self, server_id: str, operation: str) -> None:
        self.server_id = server_id
        self.operation = operation
        SSHError.__init__(
            self,
            f"Sudo authentication failed for server '{server_id}' "
            f"during operation '{operation}'.",
        )
