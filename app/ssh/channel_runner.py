"""Low-level, monotonic-deadline execution for one SSH channel."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from time import monotonic, sleep

import paramiko

from app.utils.errors import CommandTimeoutError, SSHRemoteEOFError


@dataclass(frozen=True, slots=True)
class ChannelOutput:
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float


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

    def run(self, command: str, stdin_text: str | None = None) -> ChannelOutput:
        started = self._clock()
        deadline = started + max(self._timeout, 0.0)
        channel = None
        stdout = bytearray()
        stderr = bytearray()
        try:
            channel = self._transport.open_session(timeout=self._timeout)
            channel.settimeout(self._timeout)
            channel.exec_command(command)
            if stdin_text is not None:
                channel.sendall(stdin_text.encode("utf-8"))
                channel.shutdown_write()

            while True:
                self._drain(channel, stdout, stderr)
                if channel.exit_status_ready():
                    exit_code = channel.recv_exit_status()
                    self._drain(channel, stdout, stderr)
                    return ChannelOutput(
                        exit_code=exit_code,
                        stdout=stdout.decode("utf-8", errors="replace"),
                        stderr=stderr.decode("utf-8", errors="replace"),
                        duration_seconds=max(self._clock() - started, 0.0),
                    )
                if channel.closed or channel.eof_received:
                    raise SSHRemoteEOFError(self._server_id, self._operation)

                remaining = deadline - self._clock()
                if remaining <= 0:
                    raise CommandTimeoutError(self._server_id, self._operation)
                self._sleeper(min(0.01, remaining))
        except CommandTimeoutError:
            raise
        except SSHRemoteEOFError:
            raise
        except TimeoutError:
            raise CommandTimeoutError(self._server_id, self._operation) from None
        except (EOFError, OSError, paramiko.SSHException):
            raise SSHRemoteEOFError(self._server_id, self._operation) from None
        finally:
            if channel is not None:
                try:
                    channel.close()
                except (OSError, paramiko.SSHException):
                    pass

    @staticmethod
    def _drain(channel, stdout: bytearray, stderr: bytearray) -> None:
        while channel.recv_ready():
            stdout.extend(channel.recv(65536))
        while channel.recv_stderr_ready():
            stderr.extend(channel.recv_stderr(65536))
