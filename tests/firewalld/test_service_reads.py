from dataclasses import FrozenInstanceError

import pytest
import paramiko

from app.firewalld.service import (
    ConnectionCheck,
    ConnectionTestResult,
    FirewalldInfo,
    FirewalldService,
)
from app.ssh.host_keys import HostKeyChallenge
from app.utils.errors import (
    CommandTimeoutError,
    FirewallCommandError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
    PermissionDeniedError,
    SSHAuthenticationError,
    SudoAuthenticationRequiredError,
    UnknownHostKeyError,
    UnsupportedFirewalldFeatureError,
)
from tests.firewalld.fakes import (
    ScriptedExecutor,
    install_standard_snapshot_script,
    zone_output,
)


@pytest.fixture
def scripted_executor() -> ScriptedExecutor:
    return ScriptedExecutor()


def test_result_records_are_frozen_slotted_and_normalize_check_sequences():
    check = ConnectionCheck("hostname", True, "Remote hostname read successfully.")
    result = ConnectionTestResult(
        hostname="web01",
        distribution="Fedora Linux 42",
        effective_uid=0,
        firewalld=FirewalldInfo(installed=True, running=True, version="2.3.1"),
        checks=[check],
    )

    assert result.checks == (check,)
    assert not hasattr(result, "__dict__")
    with pytest.raises(FrozenInstanceError):
        result.hostname = "changed"


def test_detection_reports_running_version_and_forwards_only_in_memory_password(scripted_executor):
    scripted_executor.respond("get_state", stdout="running\n")
    scripted_executor.respond("get_version", stdout="2.3.1\n")

    info = FirewalldService(scripted_executor, "web01").detect(sudo_password="one-use")

    assert info == FirewalldInfo(installed=True, running=True, version="2.3.1")
    assert [call.sudo_password for call in scripted_executor.calls] == ["one-use", "one-use"]
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    ("exit_code", "stderr", "expected"),
    [
        (127, "/bin/sh: firewall-cmd: command not found\n", FirewalldInfo(False, False, None)),
        (252, "FirewallD is not running\n", FirewalldInfo(True, False, None)),
    ],
)
def test_detection_distinguishes_missing_and_stopped_without_requesting_version(
    scripted_executor, exit_code, stderr, expected
):
    scripted_executor.respond("get_state", exit_code=exit_code, stderr=stderr)

    assert FirewalldService(scripted_executor, "web01").detect() == expected
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    ("stderr", "error_type"),
    [
        ("firewall-cmd: command not found", FirewalldNotInstalledError),
        ("FirewallD is not running", FirewalldNotRunningError),
        ("Authorization failed: permission denied", PermissionDeniedError),
        ("firewall-cmd: error: unrecognized arguments: --get-services", UnsupportedFirewalldFeatureError),
        ("ERROR: an ordinary remote failure", FirewallCommandError),
    ],
)
def test_failed_read_results_are_centrally_classified_into_safe_typed_errors(
    scripted_executor, stderr, error_type
):
    scripted_executor.respond("list_available_services", exit_code=1, stderr=stderr)

    with pytest.raises(error_type) as error:
        FirewalldService(scripted_executor, "web01").list_available_services()

    assert error.value.operation == "list_available_services"
    assert error.value.server_id == "web01"
    assert stderr not in str(error.value)


def test_classified_error_does_not_leak_credentials_or_raw_output_through_exception_chain(
    scripted_executor,
):
    scripted_executor.respond(
        "list_available_services",
        exit_code=1,
        stdout="hunter2 raw stdout",
        stderr="permission denied for hunter2",
    )

    with pytest.raises(PermissionDeniedError) as error:
        FirewalldService(scripted_executor, "web01").list_available_services(
            sudo_password="hunter2"
        )

    rendered = f"{error.value!r} {error.value} {error.value.__cause__!r} {error.value.__context__!r}"
    assert "hunter2" not in rendered
    assert "raw stdout" not in rendered


@pytest.mark.parametrize(
    "signal",
    [
        SSHAuthenticationError("web01"),
        CommandTimeoutError("web01", "list_available_services"),
        SudoAuthenticationRequiredError("web01", "list_available_services"),
        UnknownHostKeyError(
            HostKeyChallenge(
                "web01",
                22,
                "ssh-rsa",
                "SHA256:abc",
                paramiko.RSAKey.generate(1024),
            )
        ),
    ],
)
def test_transport_auth_timeout_and_host_key_signals_are_not_reclassified(scripted_executor, signal):
    scripted_executor.raise_error("list_available_services", signal)

    with pytest.raises(type(signal)) as error:
        FirewalldService(scripted_executor, "web01").list_available_services()

    assert error.value is signal


def test_focused_reads_select_builders_and_task_four_parsers(scripted_executor):
    raw_rule = 'rule priority="1" family="ipv4" service name="ssh" log prefix="audit" accept'
    scripted_executor.respond("list_ports_permanent", stdout="22/tcp 8000-8100/udp\n")
    scripted_executor.respond("list_services_runtime", stdout="ssh http\n")
    scripted_executor.respond("list_available_services", stdout="ssh http https\n")
    scripted_executor.respond("list_zones_permanent", stdout="public internal\n")
    scripted_executor.respond("list_interfaces_runtime", stdout="eth0 br+0\n")
    scripted_executor.respond("list_rich_rules_runtime", stdout=f"{raw_rule}\n")
    service = FirewalldService(scripted_executor, "web01")

    assert service.list_ports("public", permanent=True) == ("22/tcp", "8000-8100/udp")
    assert service.list_services("public") == ("ssh", "http")
    assert service.list_available_services() == ("ssh", "http", "https")
    assert service.list_zones(permanent=True) == ("public", "internal")
    assert service.get_interfaces("public") == ("eth0", "br+0")
    (rule,) = service.list_rich_rules("public")
    assert rule.rule == raw_rule
    assert rule.action is None
    rich_call = scripted_executor.calls[-1].spec
    assert rich_call.argv == ("firewall-cmd", "--zone=public", "--list-rich-rules")
    assert raw_rule not in rich_call.argv
    scripted_executor.assert_exhausted()


def test_connection_test_returns_fixed_named_checks_and_uses_read_only_probes(scripted_executor):
    scripted_executor.respond("hostname", stdout="web01.example.test\n")
    scripted_executor.respond(
        "distribution", stdout='NAME=Fedora\nPRETTY_NAME="Fedora Linux 42 (Server Edition)"\n'
    )
    scripted_executor.respond("effective_uid", stdout="1000\n")
    scripted_executor.respond("get_state", stdout="running\n")
    scripted_executor.respond("get_version", stdout="2.3.1\n")

    result = FirewalldService(scripted_executor, "web01").connection_test()

    assert result == ConnectionTestResult(
        hostname="web01.example.test",
        distribution="Fedora Linux 42 (Server Edition)",
        effective_uid=1000,
        firewalld=FirewalldInfo(True, True, "2.3.1"),
        checks=(
            ConnectionCheck("hostname", True, "Remote hostname read successfully."),
            ConnectionCheck("distribution", True, "Remote distribution read successfully."),
            ConnectionCheck("effective_uid", True, "Remote effective UID read successfully."),
            ConnectionCheck("firewalld", True, "Firewalld is running."),
        ),
    )
    assert [call.spec.operation for call in scripted_executor.calls] == [
        "hostname",
        "distribution",
        "effective_uid",
        "get_state",
        "get_version",
    ]
    mutation_options = ("--add-", "--remove-", "--set-", "--reload", "--complete-reload")
    assert all(
        not any(option in argument for option in mutation_options)
        for call in scripted_executor.calls
        for argument in call.spec.argv
    )


@pytest.mark.parametrize(
    ("exit_code", "stderr", "info", "message"),
    [
        (127, "firewall-cmd: command not found", FirewalldInfo(False, False, None), "Firewalld is not installed."),
        (252, "FirewallD is not running", FirewalldInfo(True, False, None), "Firewalld is not running."),
    ],
)
def test_connection_test_has_fixed_missing_and_stopped_firewalld_messages(
    scripted_executor, exit_code, stderr, info, message
):
    scripted_executor.respond("hostname", stdout="web01\n")
    scripted_executor.respond("distribution", stdout="NAME=Fedora\n")
    scripted_executor.respond("effective_uid", stdout="0\n")
    scripted_executor.respond("get_state", exit_code=exit_code, stderr=stderr)

    result = FirewalldService(scripted_executor, "web01").connection_test()

    assert result.firewalld == info
    assert result.checks[-1] == ConnectionCheck("firewalld", False, message)
    scripted_executor.assert_exhausted()


def test_connection_test_records_safe_failures_but_continues_fixed_probes(scripted_executor):
    scripted_executor.respond("hostname", exit_code=1, stderr="private remote detail")
    scripted_executor.respond("distribution", stdout="NAME=Fedora\n")
    scripted_executor.respond("effective_uid", stdout="not-a-uid\n")
    scripted_executor.respond("get_state", exit_code=1, stderr="permission denied: secret")

    result = FirewalldService(scripted_executor, "web01").connection_test()

    assert result.hostname is None
    assert result.distribution == "Fedora"
    assert result.effective_uid is None
    assert result.firewalld == FirewalldInfo(True, False, None)
    assert result.checks == (
        ConnectionCheck("hostname", False, "Unable to read remote hostname."),
        ConnectionCheck("distribution", True, "Remote distribution read successfully."),
        ConnectionCheck("effective_uid", False, "Unable to read remote effective UID."),
        ConnectionCheck("firewalld", False, "Unable to inspect firewalld."),
    )
    assert "secret" not in repr(result)
    scripted_executor.assert_exhausted()


def test_snapshot_loads_global_metadata_active_interfaces_and_both_zone_targets(scripted_executor):
    install_standard_snapshot_script(scripted_executor)

    snapshot = FirewalldService(scripted_executor, "web01").load_snapshot()

    assert snapshot.hostname == "web01.example.test"
    assert snapshot.distribution == "Fedora Linux 42 (Server Edition)"
    assert snapshot.firewalld_running is True
    assert snapshot.firewalld_version == "2.3.1"
    assert snapshot.default_zone == "public"
    assert [zone.name for zone in snapshot.runtime_zones] == ["public", "internal"]
    assert snapshot.runtime_zones[0].interfaces == ("eth0",)
    assert snapshot.runtime_zones[1].interfaces == ("eth1",)
    assert [zone.name for zone in snapshot.permanent_zones] == ["public"]
    assert snapshot.permanent_zones[0].permanent is True
    assert snapshot.available_services == ("ssh", "http", "https", "dns")
    assert snapshot.stale is False
    operations = [call.spec.operation for call in scripted_executor.calls]
    assert operations.count("get_default_zone") == 1
    assert "get_default_zone_permanent" not in operations
    assert "list_active_zones" in operations
    scripted_executor.assert_exhausted()


def test_snapshot_keeps_permanent_state_when_one_runtime_zone_detail_fails(scripted_executor):
    scripted_executor.respond("hostname", stdout="web01\n")
    scripted_executor.respond("distribution", stdout="NAME=Fedora\n")
    scripted_executor.respond("get_state", stdout="running\n")
    scripted_executor.respond("get_version", stdout="2.3.1\n")
    scripted_executor.respond("get_default_zone", stdout="public\n")
    scripted_executor.respond("list_active_zones", stdout="public\n  interfaces: eth0\n")
    scripted_executor.respond("list_zones_runtime", stdout="public internal\n")
    scripted_executor.respond("get_zone_details_runtime", exit_code=1, stderr="temporary failure")
    scripted_executor.respond("get_zone_details_runtime", stdout=zone_output("internal"))
    scripted_executor.respond("list_zones_permanent", stdout="public\n")
    scripted_executor.respond("get_zone_details_permanent", stdout=zone_output("public"))
    scripted_executor.respond("list_available_services", stdout="ssh\n")

    snapshot = FirewalldService(scripted_executor, "web01").load_snapshot()

    assert [zone.name for zone in snapshot.runtime_zones] == ["internal"]
    assert [zone.name for zone in snapshot.permanent_zones] == ["public"]
    assert snapshot.permanent_zones[0].permanent is True
    assert snapshot.stale is True
    scripted_executor.assert_exhausted()


def test_snapshot_keeps_runtime_state_when_permanent_zone_inventory_fails(scripted_executor):
    scripted_executor.respond("hostname", stdout="web01\n")
    scripted_executor.respond("distribution", stdout="NAME=Fedora\n")
    scripted_executor.respond("get_state", stdout="running\n")
    scripted_executor.respond("get_version", stdout="2.3.1\n")
    scripted_executor.respond("get_default_zone", stdout="public\n")
    scripted_executor.respond("list_active_zones", stdout="public\n  interfaces: eth0\n")
    scripted_executor.respond("list_zones_runtime", stdout="public\n")
    scripted_executor.respond("get_zone_details_runtime", stdout=zone_output("public"))
    scripted_executor.respond("list_zones_permanent", exit_code=1, stderr="permanent read failed")
    scripted_executor.respond("list_available_services", stdout="ssh\n")

    snapshot = FirewalldService(scripted_executor, "web01").load_snapshot()

    assert [zone.name for zone in snapshot.runtime_zones] == ["public"]
    assert snapshot.permanent_zones == ()
    assert snapshot.stale is True
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    ("stderr", "error_type"),
    [
        ("firewall-cmd: command not found", FirewalldNotInstalledError),
        ("FirewallD is not running", FirewalldNotRunningError),
    ],
)
def test_snapshot_requires_an_installed_running_daemon(scripted_executor, stderr, error_type):
    scripted_executor.respond("hostname", stdout="web01\n")
    scripted_executor.respond("distribution", stdout="NAME=Fedora\n")
    scripted_executor.respond("get_state", exit_code=1, stderr=stderr)

    with pytest.raises(error_type):
        FirewalldService(scripted_executor, "web01").load_snapshot()

    scripted_executor.assert_exhausted()
