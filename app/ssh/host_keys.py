"""Application-owned OpenSSH known-hosts trust management."""

import base64
import hashlib
import os
import string
import tempfile
from dataclasses import dataclass
from pathlib import Path

import paramiko

from app.utils.errors import (
    ChangedHostKeyError,
    HostKeyStoreError,
    InvalidHostTokenError,
    UnknownHostKeyError,
)


_RAW_HOST_CHARACTERS = frozenset(string.ascii_letters + string.digits + "._-:%")


def validate_host_token(host: str) -> None:
    """Accept only portable raw host tokens, never OpenSSH host patterns."""
    if not host or any(character not in _RAW_HOST_CHARACTERS for character in host):
        raise InvalidHostTokenError()


@dataclass(frozen=True, slots=True)
class HostKeyChallenge:
    """The safe information shown before explicitly trusting a host key."""

    host: str
    port: int
    algorithm: str
    fingerprint_sha256: str
    key: paramiko.PKey


class HostKeyStore:
    """Loads, verifies, and atomically persists application SSH host trust."""

    def __init__(self, known_hosts_file: Path) -> None:
        self._known_hosts_file = Path(known_hosts_file)

    def load(self) -> paramiko.HostKeys:
        """Return the trusted keys, without creating a file for an empty store."""
        keys = paramiko.HostKeys()
        if not self._known_hosts_file.exists():
            return keys

        try:
            keys.load(str(self._known_hosts_file))
        except (
            OSError,
            UnicodeError,
            paramiko.SSHException,
            paramiko.hostkeys.InvalidHostKey,
        ):
            raise HostKeyStoreError() from None
        return keys

    def challenge(self, host: str, port: int, key: paramiko.PKey) -> HostKeyChallenge:
        """Build the canonical confirmation payload for a presented host key."""
        validate_host_token(host)
        return HostKeyChallenge(
            host=host,
            port=port,
            algorithm=key.get_name(),
            fingerprint_sha256=self._fingerprint(key),
            key=key,
        )

    def verify(self, host: str, port: int, key: paramiko.PKey) -> None:
        """Verify a presented key or raise a typed explicit-trust error."""
        validate_host_token(host)
        trusted_key = self._trusted_key(host, port, key.get_name())
        if trusted_key is None:
            raise UnknownHostKeyError(self.challenge(host, port, key))
        if trusted_key != key:
            raise ChangedHostKeyError(
                host,
                port,
                self._fingerprint(trusted_key),
                self._fingerprint(key),
            )

    def trust(self, challenge: HostKeyChallenge) -> None:
        """Persist an explicitly confirmed, previously unknown host key."""
        validate_host_token(challenge.host)
        if not self._challenge_is_consistent(challenge):
            raise HostKeyStoreError()

        keys = self.load()
        host_name = self._openssh_host_name(challenge.host, challenge.port)
        trusted_key = self._lookup_key(keys, host_name, challenge.algorithm)
        if trusted_key is not None:
            if trusted_key != challenge.key:
                raise ChangedHostKeyError(
                    challenge.host,
                    challenge.port,
                    self._fingerprint(trusted_key),
                    challenge.fingerprint_sha256,
                )
            return

        keys.add(host_name, challenge.algorithm, challenge.key)
        self._save_atomically(keys)

    def _trusted_key(self, host: str, port: int, algorithm: str) -> paramiko.PKey | None:
        return self._lookup_key(self.load(), self._openssh_host_name(host, port), algorithm)

    @staticmethod
    def _lookup_key(keys: paramiko.HostKeys, host_name: str, algorithm: str) -> paramiko.PKey | None:
        matching_keys = keys.lookup(host_name)
        return None if matching_keys is None else matching_keys.get(algorithm)

    @staticmethod
    def _openssh_host_name(host: str, port: int) -> str:
        return host if port == 22 else f"[{host}]:{port}"

    @staticmethod
    def _fingerprint(key: paramiko.PKey) -> str:
        digest = hashlib.sha256(key.asbytes()).digest()
        encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{encoded}"

    def _save_atomically(self, keys: paramiko.HostKeys) -> None:
        descriptor: int | None = None
        temporary_file: Path | None = None
        try:
            self._known_hosts_file.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{self._known_hosts_file.name}.",
                suffix=".tmp",
                dir=self._known_hosts_file.parent,
            )
            temporary_file = Path(temporary_name)
            os.close(descriptor)
            descriptor = None
            keys.save(str(temporary_file))
            with temporary_file.open("r+b") as output:
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_file, self._known_hosts_file)
        except (OSError, paramiko.SSHException):
            raise HostKeyStoreError() from None
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if temporary_file is not None:
                try:
                    temporary_file.unlink(missing_ok=True)
                except OSError:
                    pass

    def _challenge_is_consistent(self, challenge: HostKeyChallenge) -> bool:
        return (
            challenge.algorithm == challenge.key.get_name()
            and challenge.fingerprint_sha256 == self._fingerprint(challenge.key)
        )
