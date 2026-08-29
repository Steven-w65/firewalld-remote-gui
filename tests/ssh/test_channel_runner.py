from __future__ import annotations

import time
from threading import Event, Thread

import paramiko
import pytest

from app.config.models import ServerConfig
from app.models.command import CommandSpec
from app.ssh.channel_runner import ChannelRunner
from app.ssh.host_keys import HostKeyStore
from app.ssh.ssh_manager import SSHManager
from app.utils.errors import (
    CommandTimeoutError,
    SSHRemoteEOFError,
    SudoAuthenticationRequiredError,
)
from tests.ssh.fakes import FakeClock, FakeSSHClient


def runner_with_result(*, timeout=1.0, clock=None, **result_kwargs):
    client = FakeSSHClient(paramiko.RSAKey.generate(1024), clock=clock)
    exit_code = result_kwargs.pop("exit_code", 0)
    stdout = result_kwargs.pop("stdout", "")
    stderr = result_kwargs.pop("stderr", "")
    client.queue_result(exit_code, stdout, stderr, **result_kwargs)
    runner = ChannelRunner(
        client.transport,
        timeout,
        "edge-1",
        "probe",
        clock=clock if clock is not None else time.monotonic,
        sleeper=(lambda seconds: clock.advance(seconds)) if clock is not None else time.sleep,
    )
    return runner, client


def test_open_timeout_uses_absolute_deadline_for_paramiko_ssh_exception():
    """Catches mapping an exhausted open-session budget to remote EOF."""
    clock = FakeClock()
    runner, client = runner_with_result(
        clock=clock,
        open_advance=1.0,
        open_error=paramiko.SSHException("open timed out"),
    )

    with pytest.raises(CommandTimeoutError):
        runner.run("hostname")

    assert client.transport.open_timeouts == [1.0]


def test_setup_consuming_deadline_prevents_exec_request():
    """Catches resetting the budget after session setup."""
    clock = FakeClock()
    runner, client = runner_with_result(clock=clock, open_advance=1.1)

    with pytest.raises(CommandTimeoutError):
        runner.run("hostname")

    assert client.commands == []


def test_never_acknowledged_exec_is_bounded_and_closes_channel():
    """Catches relying on Channel.settimeout for exec request acknowledgement."""
    exec_wait = Event()
    runner, client = runner_with_result(timeout=0.03, exec_wait=exec_wait)
    completed = Event()
    caught: list[BaseException] = []

    def execute() -> None:
        try:
            runner.run("hostname")
        except BaseException as error:
            caught.append(error)
        finally:
            completed.set()

    worker = Thread(target=execute, daemon=True)
    worker.start()
    finished_within_bound = completed.wait(0.25)  # documented bounded liveness assertion
    exec_wait.set()
    worker.join(0.25)

    assert finished_within_bound
    assert len(caught) == 1 and isinstance(caught[0], CommandTimeoutError)
    assert client.transport.channels[0].close_event.wait(0.25)


def test_partial_password_sends_share_one_deadline():
    """Catches sendall resetting a full socket timeout after every partial send."""
    clock = FakeClock()
    runner, client = runner_with_result(
        clock=clock,
        send_sizes=(2, 2, 2, 2, 2, 2),
        send_advance=0.3,
    )

    with pytest.raises(CommandTimeoutError):
        runner.run("sudo -S -p '' -- firewall-cmd --state", "sudo-secret\n")

    assert client.transport.channels[0].stdin_closed is False


def test_blocked_password_send_receives_only_remaining_budget():
    """Catches a blocked send receiving the original timeout after exec setup."""
    clock = FakeClock()
    runner, client = runner_with_result(
        clock=clock,
        exec_advance=0.75,
        send_error=TimeoutError("blocked"),
    )

    with pytest.raises(CommandTimeoutError):
        runner.run("sudo -S -p '' -- firewall-cmd --state", "sudo-secret\n")

    assert client.transport.channels[0].send_timeouts == [pytest.approx(0.25)]


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_continuously_ready_output_cannot_outlive_deadline(stream):
    """Catches an unbounded inner drain loop under continuous remote output."""
    clock = FakeClock()
    kwargs = {
        f"continuous_{stream}": "x",
        "continuous_reads": 100,
        "recv_advance": 0.05,
    }
    runner, client = runner_with_result(clock=clock, **kwargs)

    with pytest.raises(CommandTimeoutError):
        runner.run("hostname")

    assert client.transport.channels[0].close_event.wait(0.25)


def test_status_before_fragmented_output_waits_for_eof_and_keeps_all_bytes():
    """Catches returning on status before delayed buffered output arrives."""
    clock = FakeClock()
    runner, _ = runner_with_result(
        clock=clock,
        stdout="first ",
        stdout_fragments=(None, "second ", None, "third"),
        status_available=True,
    )

    result = runner.run("hostname")

    assert result.stdout == "first second third"


def test_eof_before_status_is_not_misclassified_as_failure():
    """Catches treating SSH EOF as fatal before a delayed exit status arrives."""
    clock = FakeClock()
    runner, _ = runner_with_result(
        clock=clock,
        eof_before_status=True,
        eof_after_output=False,
        status_available=False,
        status_after_checks=2,
    )

    result = runner.run("hostname")

    assert result.exit_code == 0


@pytest.mark.parametrize(
    "result_kwargs",
    [
        {"closed_without_status": True, "status_available": False},
        {"exit_code": -1, "status_available": True},
    ],
)
def test_closed_or_minus_one_status_maps_to_remote_eof(result_kwargs):
    """Catches accepting Paramiko's missing-status sentinel as a command result."""
    runner, _ = runner_with_result(**result_kwargs)

    with pytest.raises(SSHRemoteEOFError):
        runner.run("hostname")


def test_fragmented_sudo_stderr_is_reassembled_before_classification(tmp_path):
    """Catches returning before a canonical sudo diagnostic is fully buffered."""
    clock = FakeClock()
    key = paramiko.RSAKey.generate(1024)
    server = ServerConfig("edge-1", "Edge", "edge.test", "operator", "ssh-secret")
    store = HostKeyStore(tmp_path / "known_hosts")
    store.trust(store.challenge(server.host, server.port, key))
    client = FakeSSHClient(key, clock=clock)
    manager = SSHManager(
        server,
        store,
        command_timeout=1.0,
        client_factory=lambda: client,
        clock=clock,
        sleeper=clock.advance,
    )
    manager.connect()
    client.queue_result(
        1,
        "",
        "",
        stderr_fragments=(None, "sudo: a password", None, " is required\n"),
    )

    with pytest.raises(SudoAuthenticationRequiredError):
        manager.execute_command(CommandSpec("state", ("firewall-cmd", "--state"), True))
