"""Timeout-aware SSH connection and approved-command execution boundary."""

from __future__ import annotations

from collections.abc import Callable
from time import monotonic, sleep

import paramiko

from app.config.models import ServerConfig
from app.firewalld.renderer import render_command, render_sudo
from app.models.command import CommandResult, CommandSpec
from app.ssh.channel_runner import ChannelRunner
from app.ssh.host_keys import HostKeyStore, validate_host_token
from app.utils.errors import (
    ChangedHostKeyError,
    HostKeyStoreError,
    InvalidHostTokenError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHConnectionTimeoutError,
    SSHRemoteEOFError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    UnknownHostKeyError,
)


class _ApplicationHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Delegate every presented host key to the application trust store."""

    def __init__(self, store: HostKeyStore, host: str, port: int) -> None:
        self._store = store
        self._host = host
        self._port = port

    def missing_host_key(
        self,
        client: paramiko.SSHClient,
        hostname: str,
        key: paramiko.PKey,
    ) -> None:
        del client, hostname
        self._store.verify(self._host, self._port, key)


class SSHManager:
    def __init__(
        self,
        server: ServerConfig,
        host_key_store: HostKeyStore,
        connect_timeout: float = 10.0,
        command_timeout: float = 20.0,
        *,
        client_factory: Callable[[], paramiko.SSHClient] = paramiko.SSHClient,
        clock: Callable[[], float] = monotonic,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self._server = server
        self._host_key_store = host_key_store
        self._connect_timeout = (
            server.connect_timeout if server.connect_timeout is not None else connect_timeout
        )
        self._command_timeout = (
            server.command_timeout if server.command_timeout is not None else command_timeout
        )
        self._client_factory = client_factory
        self._clock = clock
        self._sleeper = sleeper
        self._client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        if self.is_connected():
            return
        self.disconnect()

        try:
            validate_host_token(self._server.host)
        except InvalidHostTokenError:
            raise SSHConnectionError(self._server.id, "invalid host") from None

        client = self._client_factory()
        client.set_missing_host_key_policy(
            _ApplicationHostKeyPolicy(
                self._host_key_store,
                self._server.host,
                self._server.port,
            )
        )
        try:
            client.connect(
                hostname=self._server.host,
                port=self._server.port,
                username=self._server.username,
                password=self._server.password,
                timeout=self._connect_timeout,
                auth_timeout=self._connect_timeout,
                banner_timeout=self._connect_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise SSHConnectionError(self._server.id, "connection failed")
        except (UnknownHostKeyError, ChangedHostKeyError):
            self._close_client(client)
            raise
        except paramiko.BadHostKeyException as error:
            self._close_client(client)
            expected = self._host_key_store.challenge(
                self._server.host,
                self._server.port,
                error.expected_key,
            ).fingerprint_sha256
            actual = self._host_key_store.challenge(
                self._server.host,
                self._server.port,
                error.key,
            ).fingerprint_sha256
            raise ChangedHostKeyError(
                self._server.host,
                self._server.port,
                expected,
                actual,
            ) from None
        except paramiko.AuthenticationException:
            self._close_client(client)
            raise SSHAuthenticationError(self._server.id) from None
        except TimeoutError:
            self._close_client(client)
            raise SSHConnectionTimeoutError(self._server.id) from None
        except HostKeyStoreError:
            self._close_client(client)
            raise SSHConnectionError(self._server.id, "host-key verification failed") from None
        except (EOFError, OSError, paramiko.SSHException):
            self._close_client(client)
            raise SSHConnectionError(self._server.id, "connection failed") from None
        except SSHConnectionError:
            self._close_client(client)
            raise

        self._client = client

    def disconnect(self) -> None:
        client = self._client
        self._client = None
        if client is not None:
            self._close_client(client)

    def is_connected(self) -> bool:
        if self._client is None:
            return False
        try:
            transport = self._client.get_transport()
            return transport is not None and transport.is_active()
        except (OSError, paramiko.SSHException):
            return False

    def execute_command(
        self,
        spec: CommandSpec,
        sudo_password: str | None = None,
    ) -> CommandResult:
        if not isinstance(spec, CommandSpec):
            raise TypeError("spec must be a CommandSpec")
        if not self.is_connected() or self._client is None:
            raise SSHConnectionError(self._server.id, "not connected")

        transport = self._client.get_transport()
        if transport is None:
            raise SSHConnectionError(self._server.id, "not connected")

        use_sudo = spec.requires_privilege and self._server.username != "root"
        stdin_text: str | None = None
        if not use_sudo:
            command = render_command(spec)
        elif sudo_password is None:
            command = render_sudo(spec, "noninteractive")
        else:
            command = render_sudo(spec, "stdin")
            stdin_text = f"{sudo_password}\n"

        output = ChannelRunner(
            transport,
            self._command_timeout,
            self._server.id,
            spec.operation,
            clock=self._clock,
            sleeper=self._sleeper,
        ).run(command, stdin_text)

        if use_sudo and output.exit_code != 0:
            markers = {line.strip() for line in output.stderr.splitlines()}
            password_required = bool(
                markers
                & {
                    "sudo: a password is required",
                    "sudo: no password was provided",
                }
            )
            authentication_failed = bool(
                markers
                & {
                    "Sorry, try again.",
                    "sudo: 1 incorrect password attempt",
                }
            )
            if authentication_failed or (password_required and sudo_password is not None):
                raise SudoAuthenticationError(self._server.id, spec.operation)
            if password_required:
                raise SudoAuthenticationRequiredError(self._server.id, spec.operation)

        stdout = self._sanitize(output.stdout, sudo_password)
        stderr = self._sanitize(output.stderr, sudo_password)
        return CommandResult(
            success=output.exit_code == 0,
            exit_code=output.exit_code,
            stdout=stdout,
            stderr=stderr,
            server_id=self._server.id,
            operation=spec.operation,
            duration_seconds=output.duration_seconds,
        )

    @staticmethod
    def _close_client(client: paramiko.SSHClient) -> None:
        try:
            client.close()
        except (OSError, paramiko.SSHException):
            pass

    def _sanitize(self, value: str, sudo_password: str | None) -> str:
        credentials = (self._server.password, sudo_password)
        sanitized = value
        for credential in credentials:
            if credential:
                sanitized = sanitized.replace(credential, "[REDACTED]")
        return sanitized
