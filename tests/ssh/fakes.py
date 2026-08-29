"""Offline Paramiko-shaped fakes for SSH boundary tests."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Event

import paramiko


class FakeClock:
    def __init__(self, initial: float = 0.0) -> None:
        self.value = initial

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@dataclass(slots=True)
class FakeChannelResult:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    stdout_fragments: tuple[str | None, ...] = ()
    stderr_fragments: tuple[str | None, ...] = ()
    status_available: bool = True
    status_after_checks: int | None = None
    eof_before_status: bool = False
    eof_after_output: bool = True
    closed_without_status: bool = False
    never_completes: bool = False
    remote_eof: bool = False
    exec_error: BaseException | None = None
    exec_wait: Event | None = None
    exec_advance: float = 0.0
    send_sizes: tuple[int, ...] = ()
    send_advance: float = 0.0
    send_error: BaseException | None = None
    sendall_wait: Event | None = None
    continuous_stdout: str | None = None
    continuous_stderr: str | None = None
    continuous_reads: int = 0
    recv_advance: float = 0.0
    open_advance: float = 0.0
    open_error: BaseException | None = None
    shutdown_advance: float = 0.0


class FakeChannel:
    def __init__(
        self,
        result: FakeChannelResult,
        client: "FakeSSHClient",
        clock: FakeClock | None,
    ) -> None:
        self._result = result
        self._client = client
        self._clock = clock
        self._stdout = bytearray(result.stdout.encode("utf-8"))
        self._stderr = bytearray(result.stderr.encode("utf-8"))
        self._stdout_fragments = deque(result.stdout_fragments)
        self._stderr_fragments = deque(result.stderr_fragments)
        self._send_sizes = deque(result.send_sizes)
        self._status_checks = 0
        self._stdin = bytearray()
        self._continuous_reads_left = result.continuous_reads
        self.closed = result.closed_without_status or result.remote_eof
        self.close_event = Event()
        self.stdin_closed = False
        self.timeout: float | None = None
        self.send_timeouts: list[float | None] = []
        self.pty_requested = False

    def _advance(self, seconds: float) -> None:
        if self._clock is not None:
            self._clock.advance(seconds)

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def get_pty(self, *args, **kwargs) -> None:
        self.pty_requested = True
        raise AssertionError("SSH command execution must never request a PTY")

    def exec_command(self, command: str) -> None:
        self._client.commands.append(command)
        self._advance(self._result.exec_advance)
        if self._result.exec_wait is not None:
            self._result.exec_wait.wait()
            if self.closed:
                raise paramiko.SSHException("channel closed before exec acknowledgement")
        if self._result.exec_error is not None:
            raise self._result.exec_error

    def send(self, data: bytes) -> int:
        self.send_timeouts.append(self.timeout)
        self._advance(self._result.send_advance)
        if self._result.send_error is not None:
            raise self._result.send_error
        size = self._send_sizes.popleft() if self._send_sizes else len(data)
        size = min(max(size, 0), len(data))
        self._stdin.extend(data[:size])
        return size

    def sendall(self, data: bytes) -> None:
        if self._result.sendall_wait is not None:
            self._result.sendall_wait.wait()
        remaining = data
        while remaining:
            sent = self.send(remaining)
            remaining = remaining[sent:]

    def shutdown_write(self) -> None:
        self._advance(self._result.shutdown_advance)
        self.stdin_closed = True
        self._client.stdin_writes.append(self._stdin.decode("utf-8"))

    def _ready(self, buffer: bytearray, fragments: deque[str | None], continuous: str | None) -> bool:
        if buffer:
            return True
        if fragments:
            fragment = fragments.popleft()
            if fragment is None:
                return False
            buffer.extend(fragment.encode("utf-8"))
            return True
        return continuous is not None and self._continuous_reads_left > 0

    def recv_ready(self) -> bool:
        return self._ready(
            self._stdout,
            self._stdout_fragments,
            self._result.continuous_stdout,
        )

    def recv(self, size: int) -> bytes:
        self._advance(self._result.recv_advance)
        if self._stdout:
            data = bytes(self._stdout[:size])
            del self._stdout[:size]
            return data
        self._continuous_reads_left -= 1
        return (self._result.continuous_stdout or "").encode("utf-8")

    def recv_stderr_ready(self) -> bool:
        return self._ready(
            self._stderr,
            self._stderr_fragments,
            self._result.continuous_stderr,
        )

    def recv_stderr(self, size: int) -> bytes:
        self._advance(self._result.recv_advance)
        if self._stderr:
            data = bytes(self._stderr[:size])
            del self._stderr[:size]
            return data
        self._continuous_reads_left -= 1
        return (self._result.continuous_stderr or "").encode("utf-8")

    def _status_is_available(self) -> bool:
        if self._result.never_completes or self._result.remote_eof:
            return False
        if self._result.status_available:
            return True
        return (
            self._result.status_after_checks is not None
            and self._status_checks >= self._result.status_after_checks
        )

    def exit_status_ready(self) -> bool:
        self._status_checks += 1
        return self.closed or self._status_is_available()

    def recv_exit_status(self) -> int:
        return self._result.exit_code if self._status_is_available() else -1

    @property
    def eof_received(self) -> bool:
        if self._result.never_completes:
            return False
        if self._result.eof_before_status or self._result.remote_eof:
            return True
        if not self._result.eof_after_output:
            return False
        return not (
            self._stdout
            or self._stderr
            or self._stdout_fragments
            or self._stderr_fragments
            or self._continuous_reads_left > 0
        )

    def close(self) -> None:
        self.closed = True
        self.close_event.set()
        if self._result.exec_wait is not None:
            self._result.exec_wait.set()


class FakeTransport:
    def __init__(self, client: "FakeSSHClient", clock: FakeClock | None = None) -> None:
        self._client = client
        self._clock = clock
        self.active = False
        self.channels: list[FakeChannel] = []
        self.open_timeouts: list[float | None] = []

    def is_active(self) -> bool:
        return self.active

    def open_session(self, timeout: float | None = None) -> FakeChannel:
        self.open_timeouts.append(timeout)
        if not self._client.results:
            raise AssertionError("No queued fake SSH channel result")
        result = self._client.results.pop(0)
        if self._clock is not None:
            self._clock.advance(result.open_advance)
        if result.open_error is not None:
            raise result.open_error
        channel = FakeChannel(result, self._client, self._clock)
        self.channels.append(channel)
        return channel


class FakeSSHClient:
    """A complete fake for the SSHClient methods used by SSHManager."""

    def __init__(self, server_key: paramiko.PKey, *, clock: FakeClock | None = None) -> None:
        self.server_key = server_key
        self.connect_error: BaseException | None = None
        self.connect_kwargs: dict[str, object] = {}
        self.policy: paramiko.MissingHostKeyPolicy | None = None
        self.transport = FakeTransport(self, clock)
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
        **kwargs,
    ) -> None:
        self.results.append(
            FakeChannelResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                **kwargs,
            )
        )
