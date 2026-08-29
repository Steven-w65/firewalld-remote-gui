"""Low-level, monotonic-deadline execution for one SSH channel."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from queue import Queue
from threading import Event, Thread
from time import monotonic, sleep
from typing import Any

import paramiko

from app.utils.errors import (
    CommandTimeoutError,
    SSHRemoteEOFError,
    SudoAuthenticationError,
)


@dataclass(frozen=True, slots=True)
class ChannelOutput:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


def _encode_stdin(value: str | bytes) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return None
    try:
        return value.encode("utf-8")
    except UnicodeError:
        return None


class ChannelRunner:
    """Run exactly one command without a PTY and close its channel afterward."""

    def __init__(
        self,
        transport: paramiko.Transport,
        timeout: float,
        server_id: str,
        operation: str,
        *,
        clock: Callable[[], float] = monotonic,
        sleeper: Callable[[float], None] = sleep,
    ) -> None:
        self._transport = transport
        self._timeout = timeout
        self._server_id = server_id
        self._operation = operation
        self._clock = clock
        self._sleeper = sleeper

    def run(
        self,
        command: str,
        stdin_data: str | bytes | None = None,
    ) -> ChannelOutput:
        encoded_stdin = None if stdin_data is None else _encode_stdin(stdin_data)
        if stdin_data is not None and encoded_stdin is None:
            raise SudoAuthenticationError(self._server_id, self._operation)

        started = self._clock()
        deadline = started + max(self._timeout, 0.0)
        channel = None
        stdout = bytearray()
        stderr = bytearray()
        try:
            open_timeout = max(deadline - self._clock(), 0.0)
            channel = self._transport.open_session(timeout=open_timeout)
            self._set_remaining_timeout(channel, deadline)
            self._bounded_call(
                lambda: channel.exec_command(command),
                deadline,
            )

            if encoded_stdin is not None:
                self._send_all(channel, encoded_stdin, deadline)
                self._bounded_call(channel.shutdown_write, deadline)

            exit_code: int | None = None
            while True:
                self._drain(channel, stdout, stderr, deadline)

                if exit_code is None and channel.exit_status_ready():
                    exit_code = self._bounded_call(channel.recv_exit_status, deadline)
                    if exit_code == -1:
                        raise SSHRemoteEOFError(self._server_id, self._operation)

                if channel.closed and exit_code is None:
                    raise SSHRemoteEOFError(self._server_id, self._operation)

                if exit_code is not None and (channel.eof_received or channel.closed):
                    self._drain(channel, stdout, stderr, deadline)
                    if not channel.recv_ready() and not channel.recv_stderr_ready():
                        return ChannelOutput(
                            exit_code=exit_code,
                            stdout=stdout.decode("utf-8", errors="replace"),
                            stderr=stderr.decode("utf-8", errors="replace"),
                            duration_seconds=max(self._clock() - started, 0.0),
                        )

                remaining = self._remaining(deadline)
                self._sleeper(min(0.01, remaining))
        except (CommandTimeoutError, SSHRemoteEOFError, SudoAuthenticationError):
            raise
        except TimeoutError:
            raise CommandTimeoutError(self._server_id, self._operation) from None
        except (EOFError, OSError, paramiko.SSHException):
            if self._deadline_exhausted(deadline):
                raise CommandTimeoutError(self._server_id, self._operation) from None
            raise SSHRemoteEOFError(self._server_id, self._operation) from None
        finally:
            if channel is not None:
                self._close_bounded(channel, deadline)

    def _send_all(self, channel, data: bytes, deadline: float) -> None:
        remaining_data = data
        while remaining_data:
            self._set_remaining_timeout(channel, deadline)
            sent = channel.send(remaining_data)
            if sent <= 0:
                raise SSHRemoteEOFError(self._server_id, self._operation)
            remaining_data = remaining_data[sent:]
            self._remaining(deadline)

    def _drain(
        self,
        channel,
        stdout: bytearray,
        stderr: bytearray,
        deadline: float,
    ) -> None:
        while True:
            self._remaining(deadline)
            progressed = False

            if channel.recv_ready():
                self._set_remaining_timeout(channel, deadline)
                data = channel.recv(65536)
                if data:
                    stdout.extend(data)
                    progressed = True

            self._remaining(deadline)
            if channel.recv_stderr_ready():
                self._set_remaining_timeout(channel, deadline)
                data = channel.recv_stderr(65536)
                if data:
                    stderr.extend(data)
                    progressed = True

            if not progressed:
                return

    def _bounded_call(self, operation: Callable[[], Any], deadline: float) -> Any:
        remaining = self._remaining(deadline)
        completed = Event()
        outcomes: Queue[tuple[bool, Any]] = Queue(maxsize=1)

        def invoke() -> None:
            try:
                outcomes.put((True, operation()))
            except BaseException as error:
                outcomes.put((False, error))
            finally:
                completed.set()

        Thread(target=invoke, daemon=True).start()
        if not completed.wait(remaining):
            raise CommandTimeoutError(self._server_id, self._operation)
        self._remaining(deadline)
        succeeded, value = outcomes.get_nowait()
        if succeeded:
            return value
        raise value

    def _set_remaining_timeout(self, channel, deadline: float) -> None:
        channel.settimeout(self._remaining(deadline))

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise CommandTimeoutError(self._server_id, self._operation)
        return remaining

    def _deadline_exhausted(self, deadline: float) -> bool:
        return self._clock() >= deadline

    def _close_bounded(self, channel, deadline: float) -> None:
        completed = Event()

        def close() -> None:
            try:
                channel.close()
            except (OSError, paramiko.SSHException):
                pass
            finally:
                completed.set()

        Thread(target=close, daemon=True).start()
        completed.wait(max(deadline - self._clock(), 0.0))
