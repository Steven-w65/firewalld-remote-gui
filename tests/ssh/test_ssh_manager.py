from __future__ import annotations

import traceback
from dataclasses import replace

import paramiko
import pytest

from app.config.models import ServerConfig
from app.models.command import CommandSpec
from app.ssh.host_keys import HostKeyStore
from app.ssh.ssh_manager import SSHManager
from app.utils.errors import (
    ChangedHostKeyError,
    CommandTimeoutError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHConnectionTimeoutError,
    SSHRemoteEOFError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    UnknownHostKeyError,
)
from tests.ssh.fakes import FakeSSHClient


@pytest.fixture
def server_config() -> ServerConfig:
    return ServerConfig(
        id="edge-1",
        name="Edge firewall",
        host="edge.example.test",
        username="operator",
        password="ssh-secret",
        port=2222,
    )


@pytest.fixture
def server_key() -> paramiko.RSAKey:
    return paramiko.RSAKey.generate(1024)


@pytest.fixture
def host_key_store(tmp_path, server_config, server_key) -> HostKeyStore:
    store = HostKeyStore(tmp_path / "known_hosts")
    store.trust(store.challenge(server_config.host, server_config.port, server_key))
    return store


@pytest.fixture
def fake_client(server_key) -> FakeSSHClient:
    return FakeSSHClient(server_key)


@pytest.fixture
def connected_manager(server_config, host_key_store, fake_client) -> SSHManager:
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)
    manager.connect()
    return manager


def formatted_exception(error: BaseException) -> str:
    return "".join(traceback.format_exception(error))


def assert_credential_free_error(error: BaseException, credential: str) -> None:
    escaped = credential.encode("unicode_escape").decode("ascii")
    rendered = "\n".join((str(error), repr(error), formatted_exception(error)))
    assert credential not in rendered
    assert escaped not in rendered
    assert "UnicodeEncodeError" not in rendered
    assert error.__cause__ is None
    assert error.__context__ is None
    assert credential not in repr(vars(error))
    assert escaped not in repr(vars(error))


def test_authentication_failure_maps_to_safe_domain_error(
    server_config, host_key_store, fake_client
):
    """Catches leaking Paramiko authentication details or the SSH password."""
    fake_client.connect_error = paramiko.AuthenticationException("ssh-secret")
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)

    with pytest.raises(SSHAuthenticationError, match="authentication failed") as caught:
        manager.connect()

    assert "edge-1" in str(caught.value)
    assert server_config.password not in formatted_exception(caught.value)
    assert not manager.is_connected()


@pytest.mark.parametrize(
    ("failure", "error_type"),
    [
        (OSError("name lookup failed: ssh-secret"), SSHConnectionError),
        (ConnectionRefusedError("refused: ssh-secret"), SSHConnectionError),
        (TimeoutError("timed out: ssh-secret"), SSHConnectionTimeoutError),
    ],
)
def test_connection_failures_map_to_credential_free_errors(
    server_config, host_key_store, fake_client, failure, error_type
):
    """Catches raw socket failure details escaping the SSH boundary."""
    fake_client.connect_error = failure
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)

    with pytest.raises(error_type) as caught:
        manager.connect()

    assert "edge-1" in str(caught.value)
    assert "ssh-secret" not in formatted_exception(caught.value)


def test_connection_uses_application_timeouts_unless_server_overrides_them(
    server_config, host_key_store, fake_client
):
    """Catches hard-coded timeouts that ignore application or server configuration."""
    configured = replace(server_config, connect_timeout=3.5, command_timeout=4.5)
    manager = SSHManager(
        configured,
        host_key_store,
        connect_timeout=11.0,
        command_timeout=12.0,
        client_factory=lambda: fake_client,
    )
    fake_client.queue_result(0, "ok", "")

    manager.connect()
    manager.execute_command(CommandSpec("probe", ("hostname",), False))

    assert fake_client.connect_kwargs["timeout"] == 3.5
    assert fake_client.connect_kwargs["auth_timeout"] == 3.5
    assert fake_client.connect_kwargs["banner_timeout"] == 3.5
    assert 0.0 < fake_client.transport.open_timeouts[0] <= 4.5
    assert fake_client.transport.open_timeouts[0] == pytest.approx(4.5, abs=0.01)


def test_application_timeout_defaults_are_used_when_server_has_no_override(
    server_config, host_key_store, fake_client
):
    """Catches treating optional per-server timeouts as mandatory values."""
    manager = SSHManager(
        server_config,
        host_key_store,
        connect_timeout=6.0,
        command_timeout=7.0,
        client_factory=lambda: fake_client,
    )
    fake_client.queue_result(0, "ok", "")

    manager.connect()
    manager.execute_command(CommandSpec("probe", ("hostname",), False))

    assert fake_client.connect_kwargs["timeout"] == 6.0
    assert 0.0 < fake_client.transport.open_timeouts[0] <= 7.0
    assert fake_client.transport.open_timeouts[0] == pytest.approx(7.0, abs=0.01)


def test_connect_uses_strict_application_host_key_trust_without_auto_add(
    server_config, host_key_store, fake_client
):
    """Catches system known-hosts or AutoAddPolicy replacing application trust."""
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)

    manager.connect()

    assert manager.is_connected()
    assert fake_client.policy is not None
    assert not isinstance(fake_client.policy, paramiko.AutoAddPolicy)
    assert fake_client.connect_kwargs["look_for_keys"] is False
    assert fake_client.connect_kwargs["allow_agent"] is False


def test_unknown_and_changed_host_keys_remain_distinct_typed_challenges(
    tmp_path, server_config, server_key
):
    """Catches wrapping explicit-trust decisions as generic connection failures."""
    unknown_client = FakeSSHClient(server_key)
    unknown = SSHManager(
        server_config,
        HostKeyStore(tmp_path / "unknown_hosts"),
        client_factory=lambda: unknown_client,
    )
    with pytest.raises(UnknownHostKeyError):
        unknown.connect()

    store = HostKeyStore(tmp_path / "changed_hosts")
    store.trust(store.challenge(server_config.host, server_config.port, server_key))
    changed_client = FakeSSHClient(paramiko.RSAKey.generate(1024))
    changed = SSHManager(server_config, store, client_factory=lambda: changed_client)
    with pytest.raises(ChangedHostKeyError):
        changed.connect()


def test_invalid_raw_host_is_rejected_before_client_creation(tmp_path, server_config):
    """Catches known-hosts metacharacters reaching lookup through SSHManager."""
    created = False

    def create_client():
        nonlocal created
        created = True
        raise AssertionError("invalid host must fail before creating a client")

    manager = SSHManager(
        replace(server_config, host="[edge.example.test]"),
        HostKeyStore(tmp_path / "known_hosts"),
        client_factory=create_client,
    )

    with pytest.raises(SSHConnectionError) as caught:
        manager.connect()

    assert "invalid host" in str(caught.value).lower()
    assert not created


def test_passwordless_sudo_is_attempted_first(connected_manager, fake_client):
    """Catches prompting or skipping sudo when no sudo password is supplied."""
    fake_client.queue_result(0, "running\n", "")

    result = connected_manager.execute_command(
        CommandSpec("state", ("firewall-cmd", "--state"), True)
    )

    assert result.success
    assert fake_client.commands == ["sudo -n -- firewall-cmd --state"]
    assert fake_client.stdin_writes == []


def test_required_sudo_password_returns_typed_signal(connected_manager, fake_client):
    """Catches returning canonical sudo prompting failures as ordinary results."""
    fake_client.queue_result(1, "", "sudo: a password is required\n")

    with pytest.raises(SudoAuthenticationRequiredError) as caught:
        connected_manager.execute_command(
            CommandSpec("state", ("firewall-cmd", "--state"), True)
        )

    assert "edge-1" in str(caught.value)
    assert "sudo: a password is required" not in formatted_exception(caught.value)


def test_supplied_sudo_password_uses_only_closed_channel_stdin(
    connected_manager, fake_client
):
    """Catches credentials entering commands or remaining on an open stdin stream."""
    fake_client.queue_result(0, "running\n", "")

    result = connected_manager.execute_command(
        CommandSpec("state", ("firewall-cmd", "--state"), True), "sudo-secret"
    )

    assert result.success
    assert fake_client.commands == ["sudo -S -p '' -- firewall-cmd --state"]
    assert fake_client.stdin_writes == ["sudo-secret\n"]
    assert fake_client.transport.channels[-1].stdin_closed
    assert not fake_client.transport.channels[-1].pty_requested
    assert "sudo-secret" not in repr(vars(connected_manager))


@pytest.mark.parametrize(
    ("username", "requires_privilege"),
    [("root", True), ("operator", False)],
)
def test_root_and_unprivileged_specs_bypass_sudo(
    server_config, host_key_store, fake_client, username, requires_privilege
):
    """Catches unnecessary sudo and accidental credential writes on bypass paths."""
    manager = SSHManager(
        replace(server_config, username=username),
        host_key_store,
        client_factory=lambda: fake_client,
    )
    manager.connect()
    fake_client.queue_result(0, "ok", "")

    manager.execute_command(
        CommandSpec("probe", ("printf", "%s", "a value; id"), requires_privilege),
        "unused-sudo-secret",
    )

    assert fake_client.commands == ["printf %s 'a value; id'"]
    assert fake_client.stdin_writes == []


def test_bad_sudo_password_maps_to_safe_typed_error(connected_manager, fake_client):
    """Catches exposing a failed sudo password or raw authentication stderr."""
    sudo_password = "sudo-secret"
    fake_client.queue_result(
        1,
        "",
        f"Sorry, try again.\nsudo: 1 incorrect password attempt\n{sudo_password}\n",
    )

    with pytest.raises(SudoAuthenticationError) as caught:
        connected_manager.execute_command(
            CommandSpec("state", ("firewall-cmd", "--state"), True), sudo_password
        )

    assert isinstance(caught.value, SudoAuthenticationRequiredError)
    assert sudo_password not in formatted_exception(caught.value)
    assert "incorrect password" not in formatted_exception(caught.value)


def test_noncanonical_remote_failure_is_a_sanitized_result(connected_manager, fake_client):
    """Catches misclassifying firewall stderr or returning a supplied credential."""
    fake_client.queue_result(2, "", "firewalld failed near sudo-secret")

    result = connected_manager.execute_command(
        CommandSpec("reload", ("firewall-cmd", "--reload"), True), "sudo-secret"
    )

    assert not result.success
    assert result.exit_code == 2
    assert result.stderr == "firewalld failed near [REDACTED]"
    assert "sudo-secret" not in repr(result)


def test_command_result_contains_server_operation_and_duration(connected_manager, fake_client):
    """Catches dropping the metadata needed by per-server service results."""
    fake_client.queue_result(0, "running\n", "warning\n")

    result = connected_manager.execute_command(
        CommandSpec("state", ("firewall-cmd", "--state"), True)
    )

    assert result.server_id == "edge-1"
    assert result.operation == "state"
    assert result.stdout == "running\n"
    assert result.stderr == "warning\n"
    assert result.duration_seconds >= 0.0


def test_each_execution_uses_and_closes_an_isolated_nonpty_channel(
    connected_manager, fake_client
):
    """Catches channel reuse, leaked channels, or PTY allocation."""
    fake_client.queue_result(0, "one", "")
    fake_client.queue_result(0, "two", "")

    connected_manager.execute_command(CommandSpec("one", ("hostname",), False))
    connected_manager.execute_command(CommandSpec("two", ("id", "-u"), False))

    assert len(fake_client.transport.channels) == 2
    assert all(channel.closed for channel in fake_client.transport.channels)
    assert all(not channel.pty_requested for channel in fake_client.transport.channels)


def test_command_timeout_closes_channel_and_raises_safe_error(
    server_config, host_key_store, fake_client
):
    """Catches an unbounded channel poll or a timeout that leaves the session open."""
    manager = SSHManager(
        server_config,
        host_key_store,
        command_timeout=0.0,
        client_factory=lambda: fake_client,
    )
    manager.connect()
    fake_client.queue_result(0, "", "", never_completes=True)

    with pytest.raises(CommandTimeoutError) as caught:
        manager.execute_command(CommandSpec("state", ("firewall-cmd", "--state"), True))

    assert fake_client.transport.channels[-1].closed
    assert "edge-1" in str(caught.value)
    assert "ssh-secret" not in formatted_exception(caught.value)


@pytest.mark.parametrize(
    "failure_setup",
    [
        lambda client: client.queue_result(0, "partial", "", remote_eof=True),
        lambda client: client.queue_result(0, "", "", exec_error=EOFError("ssh-secret")),
    ],
)
def test_remote_eof_maps_to_safe_domain_error(
    connected_manager, fake_client, failure_setup
):
    """Catches partial output or raw EOF details being mistaken for command success."""
    failure_setup(fake_client)

    with pytest.raises(SSHRemoteEOFError) as caught:
        connected_manager.execute_command(CommandSpec("probe", ("hostname",), False))

    assert "edge-1" in str(caught.value)
    assert "ssh-secret" not in formatted_exception(caught.value)


def test_execute_requires_an_active_connection(server_config, host_key_store, fake_client):
    """Catches command execution against a missing or stale SSH transport."""
    manager = SSHManager(server_config, host_key_store, client_factory=lambda: fake_client)

    with pytest.raises(SSHConnectionError, match="not connected"):
        manager.execute_command(CommandSpec("probe", ("hostname",), False))


def test_disconnect_is_idempotent(connected_manager, fake_client):
    """Catches a second disconnect touching an already-released client."""
    connected_manager.disconnect()
    connected_manager.disconnect()

    assert not connected_manager.is_connected()
    assert fake_client.close_calls == 1


def test_malformed_ssh_password_fails_before_client_state_without_leaking(
    server_config, host_key_store
):
    """Catches Paramiko retaining or exposing a credential encoding exception."""
    credential = "ssh-\ud800-secret"
    client_created = False

    def create_client():
        nonlocal client_created
        client_created = True
        raise AssertionError("malformed SSH credentials must fail before client creation")

    with pytest.raises(SSHAuthenticationError) as caught:
        SSHManager(
            replace(server_config, password=credential),
            host_key_store,
            client_factory=create_client,
        )

    assert not client_created
    assert_credential_free_error(caught.value, credential)


def test_malformed_sudo_password_fails_before_channel_state_without_leaking(
    connected_manager, fake_client
):
    """Catches channel creation before a supplied sudo credential is encodable."""
    credential = "sudo-\ud800-secret"
    fake_client.queue_result(0, "", "")

    with pytest.raises(SudoAuthenticationError) as caught:
        connected_manager.execute_command(
            CommandSpec("state", ("firewall-cmd", "--state"), True), credential
        )

    assert fake_client.transport.channels == []
    assert fake_client.stdin_writes == []
    assert_credential_free_error(caught.value, credential)
