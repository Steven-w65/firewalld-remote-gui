from __future__ import annotations

from collections.abc import Callable

import pytest

from app.firewalld.service import FirewalldService
from app.models.enums import ApplyTarget, TargetStatus
from app.utils.errors import (
    FirewalldNotRunningError,
    InvalidFirewallArgumentError,
    PostMutationVerificationError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
)
from tests.firewalld.fakes import ScriptedExecutor


@pytest.fixture
def scripted_executor() -> ScriptedExecutor:
    return ScriptedExecutor()


@pytest.fixture
def service(scripted_executor: ScriptedExecutor) -> FirewalldService:
    return FirewalldService(scripted_executor, "web01")


def _operations(executor: ScriptedExecutor) -> list[str]:
    return [call.spec.operation for call in executor.calls]


def test_add_port_both_runs_permanent_first_verifies_immediately_and_forwards_password(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("add_port_permanent")
    scripted_executor.respond("list_ports_permanent", stdout="22/tcp 8080/tcp\n")
    scripted_executor.respond("add_port_runtime")
    scripted_executor.respond("list_ports_runtime", stdout="22/tcp 8080/tcp\n")

    result = service.add_port(
        "public", "8080", "tcp", ApplyTarget.BOTH, sudo_password="one-use"
    )

    assert _operations(scripted_executor) == [
        "add_port_permanent",
        "list_ports_permanent",
        "add_port_runtime",
        "list_ports_runtime",
    ]
    assert [call.sudo_password for call in scripted_executor.calls] == ["one-use"] * 4
    assert scripted_executor.calls[0].spec.argv == (
        "firewall-cmd",
        "--permanent",
        "--zone=public",
        "--add-port=8080/tcp",
    )
    assert result.is_success
    assert result.permanent is not None and result.permanent.is_success
    assert result.runtime is not None and result.runtime.is_success
    scripted_executor.assert_exhausted()


def test_permanent_add_failure_does_not_suppress_runtime_retry_or_roll_back(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond(
        "add_port_permanent", exit_code=1, stderr="permission denied"
    )
    scripted_executor.respond("add_port_runtime")
    scripted_executor.respond("list_ports_runtime", stdout="8080/tcp\n")

    result = service.add_port("public", "8080", "tcp", ApplyTarget.BOTH)

    assert _operations(scripted_executor) == [
        "add_port_permanent",
        "add_port_runtime",
        "list_ports_runtime",
    ]
    assert result.is_partial
    assert result.permanent is not None
    assert result.permanent.execution_status is TargetStatus.FAILED
    assert result.permanent.verification_status is TargetStatus.NOT_RUN
    assert result.runtime is not None and result.runtime.is_success
    assert all("remove_port" not in operation for operation in _operations(scripted_executor))
    scripted_executor.assert_exhausted()


def test_zero_exit_with_missing_refreshed_port_is_verification_failure_without_retry(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("add_port_runtime")
    scripted_executor.respond("list_ports_runtime", stdout="22/tcp\n")

    result = service.add_port("public", "8080", "tcp", ApplyTarget.RUNTIME)

    assert _operations(scripted_executor) == ["add_port_runtime", "list_ports_runtime"]
    assert not result.is_success
    assert not result.is_partial
    assert result.permanent is None
    assert result.runtime is not None
    assert result.runtime.execution_status is TargetStatus.SUCCEEDED
    assert result.runtime.verification_status is TargetStatus.FAILED
    scripted_executor.assert_exhausted()


def test_permanent_verification_failure_does_not_suppress_runtime_or_roll_back(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("add_port_permanent")
    scripted_executor.respond(
        "list_ports_permanent", exit_code=1, stderr="permission denied"
    )
    scripted_executor.respond("add_port_runtime")
    scripted_executor.respond("list_ports_runtime", stdout="8080/tcp\n")

    result = service.add_port("public", "8080", "tcp", ApplyTarget.BOTH)

    assert _operations(scripted_executor) == [
        "add_port_permanent",
        "list_ports_permanent",
        "add_port_runtime",
        "list_ports_runtime",
    ]
    assert result.is_partial
    assert result.permanent is not None
    assert result.permanent.execution_status is TargetStatus.SUCCEEDED
    assert result.permanent.verification_status is TargetStatus.FAILED
    assert result.runtime is not None and result.runtime.is_success
    assert all("remove_port" not in operation for operation in _operations(scripted_executor))
    scripted_executor.assert_exhausted()


def test_remove_port_verifies_the_value_is_absent(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("remove_port_permanent")
    scripted_executor.respond("list_ports_permanent", stdout="22/tcp\n")

    result = service.remove_port("public", "8080", "tcp", ApplyTarget.PERMANENT)

    assert result.is_success
    assert result.runtime is None
    assert _operations(scripted_executor) == [
        "remove_port_permanent",
        "list_ports_permanent",
    ]
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    ("method_name", "write_operation", "refreshed", "expected_success"),
    [
        ("add_service", "add_service_runtime", "ssh http\n", True),
        ("add_service", "add_service_runtime", "ssh\n", False),
        ("remove_service", "remove_service_runtime", "ssh\n", True),
        ("remove_service", "remove_service_runtime", "ssh http\n", False),
    ],
)
def test_service_writes_verify_membership_from_the_target_inventory(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    method_name: str,
    write_operation: str,
    refreshed: str,
    expected_success: bool,
) -> None:
    scripted_executor.respond(write_operation)
    scripted_executor.respond("list_services_runtime", stdout=refreshed)

    method: Callable[..., object] = getattr(service, method_name)
    result = method("public", "http", ApplyTarget.RUNTIME)

    assert result.is_success is expected_success
    assert _operations(scripted_executor) == [write_operation, "list_services_runtime"]
    scripted_executor.assert_exhausted()


_RICH_RULE = (
    'rule family="ipv4" source address="192.0.2.0/24" '
    'service name="ssh" accept'
)


@pytest.mark.parametrize(
    ("method_name", "write_operation", "refreshed", "expected_success"),
    [
        ("add_rich_rule", "add_rich_rule_runtime", _RICH_RULE + "\n", True),
        ("add_rich_rule", "add_rich_rule_runtime", "", False),
        ("remove_rich_rule", "remove_rich_rule_runtime", "", True),
        ("remove_rich_rule", "remove_rich_rule_runtime", _RICH_RULE + "\n", False),
    ],
)
def test_rich_rule_writes_verify_the_exact_structured_rule(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    method_name: str,
    write_operation: str,
    refreshed: str,
    expected_success: bool,
) -> None:
    scripted_executor.respond(write_operation)
    scripted_executor.respond("list_rich_rules_runtime", stdout=refreshed)

    method: Callable[..., object] = getattr(service, method_name)
    result = method(
        "public",
        source="192.0.2.0/24",
        destination=None,
        service="ssh",
        port=None,
        protocol=None,
        action="accept",
        target=ApplyTarget.RUNTIME,
    )

    assert result.is_success is expected_success
    assert _operations(scripted_executor) == [
        write_operation,
        "list_rich_rules_runtime",
    ]
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    (
        "method_name",
        "write_operation",
        "list_operation",
        "rule",
        "kwargs",
        "target",
        "refreshed",
    ),
    [
        (
            "add_rich_rule",
            "add_rich_rule_runtime",
            "list_rich_rules_runtime",
            'rule service name="ssh" accept',
            {"service": "ssh", "port": None, "protocol": None, "action": "accept"},
            ApplyTarget.RUNTIME,
            'rule service name="ssh" accept\n',
        ),
        (
            "remove_rich_rule",
            "remove_rich_rule_permanent",
            "list_rich_rules_permanent",
            'rule port port="8443" protocol="tcp" drop',
            {"service": None, "port": "8443", "protocol": "tcp", "action": "drop"},
            ApplyTarget.PERMANENT,
            "",
        ),
    ],
)
def test_addressless_rich_rule_writes_verify_parser_owned_structured_rules(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    method_name: str,
    write_operation: str,
    list_operation: str,
    rule: str,
    kwargs: dict[str, str | None],
    target: ApplyTarget,
    refreshed: str,
) -> None:
    """Catches write verification rejecting canonical parser-recognized addressless rules."""
    scripted_executor.respond(write_operation)
    scripted_executor.respond(list_operation, stdout=refreshed)

    method: Callable[..., object] = getattr(service, method_name)
    result = method(
        "public",
        source=None,
        destination=None,
        target=target,
        **kwargs,
    )

    assert result.is_success
    assert _operations(scripted_executor) == [write_operation, list_operation]
    assert scripted_executor.calls[0].spec.argv[-1].endswith(rule)
    scripted_executor.assert_exhausted()


def test_change_interface_zone_verifies_each_target_inventory(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("change_interface_zone_permanent")
    scripted_executor.respond("list_interfaces_permanent", stdout="eth0\n")
    scripted_executor.respond("change_interface_zone_runtime")
    scripted_executor.respond("list_interfaces_runtime", stdout="eth0\n")

    result = service.change_interface_zone(
        "eth0", "internal", ApplyTarget.BOTH
    )

    assert result.is_success
    assert _operations(scripted_executor) == [
        "change_interface_zone_permanent",
        "list_interfaces_permanent",
        "change_interface_zone_runtime",
        "list_interfaces_runtime",
    ]
    scripted_executor.assert_exhausted()


def test_set_default_zone_requires_both_and_executes_and_verifies_global_effect_once(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("set_default_zone")
    scripted_executor.respond("get_default_zone", stdout="internal\n")

    result = service.set_default_zone("internal", ApplyTarget.BOTH)

    assert _operations(scripted_executor) == ["set_default_zone", "get_default_zone"]
    assert result.is_success
    assert result.runtime is not None and result.runtime.target is ApplyTarget.RUNTIME
    assert result.permanent is not None and result.permanent.target is ApplyTarget.PERMANENT
    assert result.runtime.result is result.permanent.result
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize("target", [ApplyTarget.RUNTIME, ApplyTarget.PERMANENT])
def test_set_default_zone_rejects_a_scoped_target_before_execution(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    target: ApplyTarget,
) -> None:
    with pytest.raises(InvalidFirewallArgumentError, match="Invalid target"):
        service.set_default_zone("internal", target)

    assert scripted_executor.calls == []


def test_global_default_zone_verification_failure_is_reported_for_both_views(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("set_default_zone")
    scripted_executor.respond("get_default_zone", stdout="public\n")

    result = service.set_default_zone("internal", ApplyTarget.BOTH)

    assert not result.is_success
    assert result.runtime is not None
    assert result.permanent is not None
    assert result.runtime.verification_status is TargetStatus.FAILED
    assert result.permanent.verification_status is TargetStatus.FAILED
    assert _operations(scripted_executor) == ["set_default_zone", "get_default_zone"]
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    ("method_name", "write_operation", "args"),
    [
        ("set_default_zone", "set_default_zone", ("internal", ApplyTarget.BOTH)),
        ("reload_firewalld", "reload", (ApplyTarget.BOTH,)),
    ],
)
def test_global_write_failure_is_mirrored_without_verification_retry_or_rollback(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    method_name: str,
    write_operation: str,
    args: tuple[object, ...],
) -> None:
    scripted_executor.respond(write_operation, exit_code=1, stderr="permission denied")

    method: Callable[..., object] = getattr(service, method_name)
    result = method(*args)

    assert _operations(scripted_executor) == [write_operation]
    assert not result.is_success
    assert result.runtime is not None and result.permanent is not None
    assert result.runtime.execution_status is TargetStatus.FAILED
    assert result.permanent.execution_status is TargetStatus.FAILED
    assert result.runtime.verification_status is TargetStatus.NOT_RUN
    assert result.permanent.verification_status is TargetStatus.NOT_RUN
    scripted_executor.assert_exhausted()


def test_reload_requires_both_and_executes_and_verifies_global_effect_once(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond("reload")
    scripted_executor.respond("get_state", stdout="running\n")

    result = service.reload_firewalld(ApplyTarget.BOTH, sudo_password="one-use")

    assert result.is_success
    assert _operations(scripted_executor) == ["reload", "get_state"]
    assert [call.sudo_password for call in scripted_executor.calls] == ["one-use"] * 2
    assert result.runtime is not None and result.permanent is not None
    assert result.runtime.result is result.permanent.result
    assert result.operation == "reload_firewalld"
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize(
    "verification_error",
    (
        SudoAuthenticationRequiredError("web01", "get_state"),
        SudoAuthenticationError("web01", "get_state"),
    ),
)
def test_reload_post_mutation_auth_verification_raises_safe_phase_error_without_rewrite(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    verification_error: Exception,
) -> None:
    scripted_executor.respond("reload")
    scripted_executor.raise_error("get_state", verification_error)

    with pytest.raises(RuntimeError) as raised:
        service.reload_firewalld(ApplyTarget.BOTH, sudo_password="one-use")

    assert isinstance(raised.value, PostMutationVerificationError)
    assert not isinstance(raised.value, SudoAuthenticationRequiredError)
    assert raised.value.__context__ is None
    assert "one-use" not in repr(raised.value)
    assert _operations(scripted_executor) == ["reload", "get_state"]
    scripted_executor.assert_exhausted()


@pytest.mark.parametrize("target", [ApplyTarget.RUNTIME, ApplyTarget.PERMANENT])
def test_reload_rejects_a_scoped_target_before_execution(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
    target: ApplyTarget,
) -> None:
    with pytest.raises(InvalidFirewallArgumentError, match="Invalid target"):
        service.reload_firewalld(target)

    assert scripted_executor.calls == []


def test_terminal_daemon_state_change_from_a_write_propagates(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    scripted_executor.respond(
        "add_service_permanent", exit_code=1, stderr="Firewalld is not running"
    )

    with pytest.raises(FirewalldNotRunningError):
        service.add_service("public", "http", ApplyTarget.BOTH)

    assert _operations(scripted_executor) == ["add_service_permanent"]
    scripted_executor.assert_exhausted()


def test_sudo_signal_from_a_write_propagates_without_becoming_a_partial_result(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    signal = SudoAuthenticationRequiredError("web01", "remove_service_runtime")
    scripted_executor.raise_error("remove_service_runtime", signal)

    with pytest.raises(SudoAuthenticationRequiredError) as caught:
        service.remove_service(
            "public", "http", ApplyTarget.RUNTIME, sudo_password="bad"
        )

    assert caught.value is signal
    assert _operations(scripted_executor) == ["remove_service_runtime"]
    scripted_executor.assert_exhausted()


def test_sudo_required_after_permanent_mutation_returns_phase_aware_result_without_runtime_write(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    """Catches a full-operation retry duplicating a mutation after verification auth."""
    scripted_executor.respond("add_port_permanent")
    scripted_executor.raise_error(
        "list_ports_permanent",
        SudoAuthenticationRequiredError("web01", "list_ports_permanent"),
    )

    result = service.add_port("public", "8080", "tcp", ApplyTarget.BOTH)

    assert _operations(scripted_executor) == [
        "add_port_permanent",
        "list_ports_permanent",
    ]
    assert result.permanent is not None
    assert result.permanent.execution_status is TargetStatus.SUCCEEDED
    assert result.permanent.verification_status is TargetStatus.FAILED
    assert result.permanent.authentication_failed
    assert result.runtime is not None
    assert result.runtime.execution_status is TargetStatus.NOT_RUN
    assert result.runtime.verification_status is TargetStatus.NOT_RUN
    scripted_executor.assert_exhausted()


def test_sudo_required_on_later_target_preserves_verified_permanent_success_without_retry(
    service: FirewalldService,
    scripted_executor: ScriptedExecutor,
) -> None:
    """Catches loss of the first target result when later-target auth fails."""
    scripted_executor.respond("remove_port_permanent")
    scripted_executor.respond("list_ports_permanent", stdout="22/tcp\n")
    scripted_executor.raise_error(
        "remove_port_runtime",
        SudoAuthenticationError("web01", "remove_port_runtime"),
    )

    result = service.remove_port("public", "8080", "tcp", ApplyTarget.BOTH)

    assert _operations(scripted_executor) == [
        "remove_port_permanent",
        "list_ports_permanent",
        "remove_port_runtime",
    ]
    assert result.permanent is not None and result.permanent.is_success
    assert result.runtime is not None
    assert result.runtime.execution_status is TargetStatus.FAILED
    assert result.runtime.verification_status is TargetStatus.NOT_RUN
    assert result.runtime.authentication_failed
    assert result.is_partial
    scripted_executor.assert_exhausted()
