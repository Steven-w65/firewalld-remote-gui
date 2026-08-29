"""Offline Paramiko-shaped fakes for SSH boundary tests."""

from __future__ import annotations

from dataclasses import dataclass

import paramiko


@dataclass(frozen=True, slots=True)
class FakeChannelResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    never_completes: bool = False
    remote_eof: bool = False
    exec_error: BaseException | None = None


class FakeChannel:
    def __init__(self, result: FakeChannelResult, client: "FakeSSHClient") -> None:
        self._result = result
        self._client = client
        self._stdout = bytearray(result.stdout.encode("utf-8"))
        self._stderr = bytearray(result.stderr.encode("utf-8"))
        self.closed = False
        self.stdin_closed = False
        self.timeout: float | None = None
        self.pty_requested = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def get_pty(self, *args, **kwargs) -> None:
        self.pty_requested = True
        raise AssertionError("SSH command execution must never request a PTY")

    def exec_command(self, command: str) -> None:
        if self._result.exec_error is not None:
            raise self._result.exec_error
        self._client.commands.append(command)

    def sendall(self, data: bytes) -> None:
        self._client.stdin_writes.append(data.decode("utf-8"))

    def shutdown_write(self) -> None:
        self.stdin_closed = True

    def recv_ready(self) -> bool:
        return bool(self._stdout)

    def recv(self, size: int) -> bytes:
        data = bytes(self._stdout[:size])
        del self._stdout[:size]
        return data

    def recv_stderr_ready(self) -> bool:
        return bool(self._stderr)

    def recv_stderr(self, size: int) -> bytes:
        data = bytes(self._stderr[:size])
        del self._stderr[:size]
        return data

    def exit_status_ready(self) -> bool:
        if self._result.never_completes or self._result.remote_eof:
            return False
        return not self._stdout and not self._stderr

    def recv_exit_status(self) -> int:
        return self._result.exit_code

    @property
    def eof_received(self) -> bool:
        return self._result.remote_eof and not self._stdout and not self._stderr

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def __init__(self, client: "FakeSSHClient") -> None:
        self._client = client
        self.active = False
        self.channels: list[FakeChannel] = []
        self.open_timeouts: list[float | None] = []

    def is_active(self) -> bool:
        return self.active

    def open_session(self, timeout: float | None = None) -> FakeChannel:
        self.open_timeouts.append(timeout)
        if not self._client.results:
            raise AssertionError("No queued fake SSH channel result")
        channel = FakeChannel(self._client.results.pop(0), self._client)
        self.channels.append(channel)
        return channel


class FakeSSHClient:
    """A complete fake for the SSHClient methods used by SSHManager."""

    def __init__(self, server_key: paramiko.PKey) -> None:
        self.server_key = server_key
        self.connect_error: BaseException | None = None
        self.connect_kwargs: dict[str, object] = {}
        self.policy: paramiko.MissingHostKeyPolicy | None = None
        self.transport = FakeTransport(self)
        self.results: list[FakeChannelResult] = []
        self.commands: list[str] = []
        self.stdin_writes: list[str] = []
        self.close_calls = 0

    def set_missing_host_key_policy(self, policy: paramiko.MissingHostKeyPolicy) -> None:
        self.policy = policy

    def connect(self, **kwargs) -> None:
        self.connect_kwargs = dict(kwargs)
        if self.connect_error is not None:
            raise self.connect_error
        if self.policy is None:
            raise AssertionError("A strict application host-key policy must be installed")
        self.policy.missing_host_key(self, str(kwargs["hostname"]), self.server_key)
        self.transport.active = True

    def get_transport(self) -> FakeTransport:
        return self.transport

    def close(self) -> None:
        self.close_calls += 1
        self.transport.active = False

    def queue_result(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        *,
        never_completes: bool = False,
        remote_eof: bool = False,
        exec_error: BaseException | None = None,
    ) -> None:
        self.results.append(
            FakeChannelResult(
                exit_code,
                stdout,
                stderr,
                never_completes,
                remote_eof,
                exec_error,
            )
        )
