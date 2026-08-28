from typing import Protocol


class HostKeyChallengeDetails(Protocol):
    """Safe challenge fields carried by an unknown-host-key domain error."""

    host: str
    port: int
    algorithm: str
    fingerprint_sha256: str


class ConfigurationError(ValueError):
    """Raised when the portable configuration is invalid."""


class InvalidFirewallArgumentError(ValueError):
    """Raised when a firewall operation argument fails strict validation."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid {field}: {reason}")


class HostKeyStoreError(RuntimeError):
    """Raised when the application trusted-host file cannot be handled safely."""

    def __init__(self) -> None:
        super().__init__("Unable to read or update trusted SSH host keys.")


class UnknownHostKeyError(RuntimeError):
    """Raised when a host key needs explicit user confirmation."""

    def __init__(self, challenge: HostKeyChallengeDetails) -> None:
        self.challenge = challenge
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
