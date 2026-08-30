"""Remote firewalld reads and verified writes assembled from approved commands."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol

from app.firewalld.command_builder import FirewalldCommandBuilder
from app.firewalld.parser import (
    parse_active_zones,
    parse_os_release,
    parse_rich_rules,
    parse_words,
    parse_zone_state,
)
from app.firewalld.system_commands import SystemCommandBuilder
from app.models.command import (
    CommandResult,
    CommandSpec,
    CompositeOperationResult,
    TargetResult,
)
from app.models.enums import ApplyTarget, TargetStatus
from app.models.firewall import FirewallSnapshot, RichRule, ZoneState
from app.utils.errors import (
    FirewallCommandError,
    FirewallParseError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
    InvalidFirewallArgumentError,
    PermissionDeniedError,
    PostMutationVerificationError,
    SudoAuthenticationError,
    SudoAuthenticationRequiredError,
    SystemProbeError,
    UnsupportedFirewalldFeatureError,
)


class CommandExecutor(Protocol):
    """Structural boundary implemented by SSHManager and offline test fakes."""

    def execute_command(
        self,
        spec: CommandSpec,
        sudo_password: str | None = None,
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class FirewalldInfo:
    installed: bool
    running: bool
    version: str | None


@dataclass(frozen=True, slots=True)
class ConnectionCheck:
    name: str
    passed: bool
    message: str


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    hostname: str | None
    distribution: str | None
    effective_uid: int | None
    firewalld: FirewalldInfo | None
    checks: tuple[ConnectionCheck, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "checks", tuple(self.checks))


_FIREWALL_FAILURE_RULES: tuple[
    tuple[type[FirewallCommandError], tuple[str, ...], tuple[re.Pattern[str], ...]], ...
] = (
    (
        FirewalldNotInstalledError,
        ("command not found", "firewall-cmd: not found", "no such file or directory"),
        (),
    ),
    (
        FirewalldNotRunningError,
        ("firewalld is not running", "firewalld not running"),
        (),
    ),
    (
        PermissionDeniedError,
        (
            "permission denied",
            "not authorized",
            "authorization failed",
            "not in the sudoers file",
            "is not allowed to execute",
            "may not run sudo",
        ),
        (),
    ),
    (
        UnsupportedFirewalldFeatureError,
        (
            "unrecognized arguments",
            "unknown option",
            "invalid option",
            "not a valid option",
            "no such option",
        ),
        (re.compile(r"\boption\b[^\r\n]{0,120}\bnot recognized\b"),),
    ),
)

_CONNECTION_PROBE_ERRORS = (FirewallCommandError, FirewallParseError, SystemProbeError)
_TERMINAL_FIREWALL_ERRORS = (FirewalldNotInstalledError, FirewalldNotRunningError)


class FirewalldService:
    """Execute only allowlisted commands through an injected executor."""

    def __init__(self, executor: CommandExecutor, server_id: str) -> None:
        self._executor = executor
        self._server_id = server_id

    def _execute(
        self,
        spec: CommandSpec,
        sudo_password: str | None,
    ) -> CommandResult:
        result = self._executor.execute_command(spec, sudo_password=sudo_password)
        if not isinstance(result, CommandResult):
            raise TypeError("executor must return CommandResult")
        if result.operation != spec.operation or result.server_id != self._server_id:
            raise self._generic_command_error(spec)
        if result.success and result.exit_code == 0:
            return result
        self._raise_classified(spec, result)
        raise AssertionError("unreachable")

    def _generic_command_error(self, spec: CommandSpec) -> RuntimeError:
        if spec.argv and spec.argv[0] == "firewall-cmd":
            return FirewallCommandError(self._server_id, spec.operation)
        return SystemProbeError(self._server_id, spec.operation)

    def _raise_classified(self, spec: CommandSpec, result: CommandResult) -> None:
        if not spec.argv or spec.argv[0] != "firewall-cmd":
            raise SystemProbeError(self._server_id, spec.operation)
        output = f"{result.stdout}\n{result.stderr}".casefold()
        for error_type, markers, patterns in _FIREWALL_FAILURE_RULES:
            if any(marker in output for marker in markers) or any(
                pattern.search(output) is not None for pattern in patterns
            ):
                raise error_type(self._server_id, spec.operation)
        raise FirewallCommandError(self._server_id, spec.operation)

    @staticmethod
    def _single_word(output: str, operation: str) -> str:
        words = parse_words(output)
        if len(words) != 1:
            raise FirewallParseError("word list", f"{operation} returned an invalid value")
        return words[0]

    @staticmethod
    def _effective_uid(output: str) -> int:
        value = FirewalldService._single_word(output, "effective uid")
        if not value.isascii() or not value.isdecimal():
            raise FirewallParseError("word list", "effective uid was invalid")
        return int(value)

    def detect(self, *, sudo_password: str | None = None) -> FirewalldInfo:
        info = self._detect_state(sudo_password)
        if not info.running:
            return info
        version = self._read_version(sudo_password)
        return FirewalldInfo(installed=True, running=True, version=version)

    def _detect_state(self, sudo_password: str | None) -> FirewalldInfo:
        try:
            state_result = self._execute(
                FirewalldCommandBuilder.get_state(), sudo_password
            )
        except FirewalldNotInstalledError:
            return FirewalldInfo(installed=False, running=False, version=None)
        except FirewalldNotRunningError:
            return FirewalldInfo(installed=True, running=False, version=None)

        state = " ".join(parse_words(state_result.stdout)).casefold()
        if state == "not running":
            return FirewalldInfo(installed=True, running=False, version=None)
        if state != "running":
            raise FirewallParseError("word list", "daemon state was invalid")
        return FirewalldInfo(installed=True, running=True, version=None)

    def _read_version(self, sudo_password: str | None) -> str:
        version_result = self._execute(
            FirewalldCommandBuilder.get_version(), sudo_password
        )
        return self._single_word(version_result.stdout, "firewalld version")

    def list_ports(
        self,
        zone: str,
        permanent: bool = False,
        *,
        sudo_password: str | None = None,
    ) -> tuple[str, ...]:
        result = self._execute(
            FirewalldCommandBuilder.list_ports(zone, permanent), sudo_password
        )
        return parse_words(result.stdout)

    def list_services(
        self,
        zone: str,
        permanent: bool = False,
        *,
        sudo_password: str | None = None,
    ) -> tuple[str, ...]:
        result = self._execute(
            FirewalldCommandBuilder.list_services(zone, permanent), sudo_password
        )
        return parse_words(result.stdout)

    def list_available_services(
        self, *, sudo_password: str | None = None
    ) -> tuple[str, ...]:
        result = self._execute(
            FirewalldCommandBuilder.list_available_services(), sudo_password
        )
        return parse_words(result.stdout)

    def list_zones(
        self,
        permanent: bool = False,
        *,
        sudo_password: str | None = None,
    ) -> tuple[str, ...]:
        result = self._execute(
            FirewalldCommandBuilder.list_zones(permanent), sudo_password
        )
        return parse_words(result.stdout)

    def get_interfaces(
        self,
        zone: str,
        permanent: bool = False,
        *,
        sudo_password: str | None = None,
    ) -> tuple[str, ...]:
        result = self._execute(
            FirewalldCommandBuilder.list_interfaces(zone, permanent), sudo_password
        )
        return parse_words(result.stdout)

    def list_rich_rules(
        self,
        zone: str,
        permanent: bool = False,
        *,
        sudo_password: str | None = None,
    ) -> tuple[RichRule, ...]:
        result = self._execute(
            FirewalldCommandBuilder.list_rich_rules(zone, permanent), sudo_password
        )
        return parse_rich_rules(result.stdout)

    def connection_test(
        self, *, sudo_password: str | None = None
    ) -> ConnectionTestResult:
        checks: list[ConnectionCheck] = []

        try:
            hostname_result = self._execute(
                SystemCommandBuilder.hostname(), sudo_password
            )
            hostname = self._single_word(hostname_result.stdout, "hostname")
            checks.append(
                ConnectionCheck(
                    "hostname", True, "Remote hostname read successfully."
                )
            )
        except _CONNECTION_PROBE_ERRORS:
            hostname = None
            checks.append(
                ConnectionCheck("hostname", False, "Unable to read remote hostname.")
            )

        try:
            distribution_result = self._execute(
                SystemCommandBuilder.distribution(), sudo_password
            )
            distribution = parse_os_release(distribution_result.stdout)
            checks.append(
                ConnectionCheck(
                    "distribution", True, "Remote distribution read successfully."
                )
            )
        except _CONNECTION_PROBE_ERRORS:
            distribution = None
            checks.append(
                ConnectionCheck(
                    "distribution", False, "Unable to read remote distribution."
                )
            )

        try:
            uid_result = self._execute(
                SystemCommandBuilder.effective_uid(), sudo_password
            )
            effective_uid = self._effective_uid(uid_result.stdout)
            checks.append(
                ConnectionCheck(
                    "effective_uid", True, "Remote effective UID read successfully."
                )
            )
        except _CONNECTION_PROBE_ERRORS:
            effective_uid = None
            checks.append(
                ConnectionCheck(
                    "effective_uid", False, "Unable to read remote effective UID."
                )
            )

        try:
            firewalld = self._detect_state(sudo_password)
        except (FirewallCommandError, FirewallParseError):
            firewalld = None
            checks.append(
                ConnectionCheck(
                    "firewalld_state", False, "Unable to inspect firewalld state."
                )
            )
            checks.append(
                ConnectionCheck(
                    "firewalld_version", False, "Firewalld version was not checked."
                )
            )
        else:
            if not firewalld.installed:
                firewalld_message = "Firewalld is not installed."
            elif not firewalld.running:
                firewalld_message = "Firewalld is not running."
            else:
                firewalld_message = "Firewalld is running."
            checks.append(
                ConnectionCheck(
                    "firewalld_state", firewalld.running, firewalld_message
                )
            )
            if not firewalld.running:
                checks.append(
                    ConnectionCheck(
                        "firewalld_version",
                        False,
                        "Firewalld version was not checked.",
                    )
                )
            else:
                try:
                    version = self._read_version(sudo_password)
                except FirewalldNotInstalledError:
                    firewalld = FirewalldInfo(False, False, None)
                    checks[-1] = ConnectionCheck(
                        "firewalld_state", False, "Firewalld is not installed."
                    )
                    checks.append(
                        ConnectionCheck(
                            "firewalld_version",
                            False,
                            "Unable to read firewalld version.",
                        )
                    )
                except FirewalldNotRunningError:
                    firewalld = FirewalldInfo(True, False, None)
                    checks[-1] = ConnectionCheck(
                        "firewalld_state", False, "Firewalld is not running."
                    )
                    checks.append(
                        ConnectionCheck(
                            "firewalld_version",
                            False,
                            "Unable to read firewalld version.",
                        )
                    )
                except (FirewallCommandError, FirewallParseError):
                    firewalld = FirewalldInfo(True, True, None)
                    checks.append(
                        ConnectionCheck(
                            "firewalld_version",
                            False,
                            "Unable to read firewalld version.",
                        )
                    )
                else:
                    firewalld = FirewalldInfo(True, True, version)
                    checks.append(
                        ConnectionCheck(
                            "firewalld_version",
                            True,
                            "Firewalld version read successfully.",
                        )
                    )

        return ConnectionTestResult(
            hostname=hostname,
            distribution=distribution,
            effective_uid=effective_uid,
            firewalld=firewalld,
            checks=tuple(checks),
        )

    def load_snapshot(
        self, *, sudo_password: str | None = None
    ) -> FirewallSnapshot:
        hostname_result = self._execute(SystemCommandBuilder.hostname(), sudo_password)
        hostname = self._single_word(hostname_result.stdout, "hostname")
        distribution_result = self._execute(
            SystemCommandBuilder.distribution(), sudo_password
        )
        distribution = parse_os_release(distribution_result.stdout)
        firewalld = self.detect(sudo_password=sudo_password)
        if not firewalld.installed:
            raise FirewalldNotInstalledError(self._server_id, "get_state")
        if not firewalld.running:
            raise FirewalldNotRunningError(self._server_id, "get_state")

        default_result = self._execute(
            FirewalldCommandBuilder.get_default_zone(), sudo_password
        )
        default_zone = self._single_word(default_result.stdout, "default zone")

        stale = False
        try:
            active_result = self._execute(
                FirewalldCommandBuilder.list_active_zones(), sudo_password
            )
            active_zones = parse_active_zones(active_result.stdout)
        except _TERMINAL_FIREWALL_ERRORS:
            raise
        except (FirewallCommandError, FirewallParseError):
            active_zones = {}
            stale = True

        runtime_zones, runtime_stale = self._load_zones(
            permanent=False,
            active_zones=active_zones,
            sudo_password=sudo_password,
        )
        permanent_zones, permanent_stale = self._load_zones(
            permanent=True,
            active_zones={},
            sudo_password=sudo_password,
        )
        stale = stale or runtime_stale or permanent_stale

        try:
            available_services = self.list_available_services(
                sudo_password=sudo_password
            )
        except _TERMINAL_FIREWALL_ERRORS:
            raise
        except (FirewallCommandError, FirewallParseError):
            available_services = ()
            stale = True

        return FirewallSnapshot(
            hostname=hostname,
            distribution=distribution,
            firewalld_running=True,
            firewalld_version=firewalld.version,
            default_zone=default_zone,
            runtime_zones=runtime_zones,
            permanent_zones=permanent_zones,
            available_services=available_services,
            stale=stale,
        )

    def _load_zones(
        self,
        *,
        permanent: bool,
        active_zones: dict[str, tuple[str, ...]],
        sudo_password: str | None,
    ) -> tuple[tuple[ZoneState, ...], bool]:
        try:
            names = self.list_zones(
                permanent=permanent, sudo_password=sudo_password
            )
        except _TERMINAL_FIREWALL_ERRORS:
            raise
        except (FirewallCommandError, FirewallParseError):
            return (), True

        zones: list[ZoneState] = []
        stale = False
        for name in names:
            try:
                spec = FirewalldCommandBuilder.get_zone_details(name, permanent)
                result = self._execute(spec, sudo_password)
                zone = parse_zone_state(name, result.stdout, permanent)
                active_interfaces = active_zones.get(name, ())
                if not permanent and active_interfaces:
                    zone = replace(zone, interfaces=active_interfaces)
                zones.append(zone)
            except _TERMINAL_FIREWALL_ERRORS:
                raise
            except (
                FirewallCommandError,
                FirewallParseError,
                InvalidFirewallArgumentError,
            ):
                stale = True
        return tuple(zones), stale

    @staticmethod
    def _selected_targets(target: ApplyTarget) -> tuple[ApplyTarget, ...]:
        if target is ApplyTarget.BOTH:
            return (ApplyTarget.PERMANENT, ApplyTarget.RUNTIME)
        if target in (ApplyTarget.RUNTIME, ApplyTarget.PERMANENT):
            return (target,)
        raise InvalidFirewallArgumentError("target", "must be runtime, permanent, or both")

    @staticmethod
    def _require_global_target(target: ApplyTarget) -> None:
        if target is not ApplyTarget.BOTH:
            raise InvalidFirewallArgumentError(
                "target", "global firewalld operations require both"
            )

    @staticmethod
    def _target_failure(
        target: ApplyTarget,
        *,
        result: CommandResult | None = None,
        verification: bool = False,
    ) -> TargetResult:
        return TargetResult(
            target=target,
            execution_status=(
                TargetStatus.SUCCEEDED if verification else TargetStatus.FAILED
            ),
            verification_status=(
                TargetStatus.FAILED if verification else TargetStatus.NOT_RUN
            ),
            result=result,
            message=(
                "Firewalld state did not match the requested change."
                if verification
                else "The firewalld change failed."
            ),
        )

    @staticmethod
    def _target_success(
        target: ApplyTarget, result: CommandResult
    ) -> TargetResult:
        return TargetResult(
            target=target,
            execution_status=TargetStatus.SUCCEEDED,
            verification_status=TargetStatus.SUCCEEDED,
            result=result,
            message="",
        )

    @staticmethod
    def _composite(
        operation: str, results: dict[ApplyTarget, TargetResult]
    ) -> CompositeOperationResult:
        return CompositeOperationResult(
            operation=operation,
            runtime=results.get(ApplyTarget.RUNTIME),
            permanent=results.get(ApplyTarget.PERMANENT),
        )

    def _apply_targets(
        self,
        operation: str,
        target: ApplyTarget,
        build: Callable[[bool], CommandSpec],
        verify: Callable[[bool], bool],
        sudo_password: str | None,
    ) -> CompositeOperationResult:
        results: dict[ApplyTarget, TargetResult] = {}
        for selected in self._selected_targets(target):
            permanent = selected is ApplyTarget.PERMANENT
            spec = build(permanent)
            try:
                command_result = self._execute(spec, sudo_password)
            except _TERMINAL_FIREWALL_ERRORS:
                raise
            except FirewallCommandError:
                results[selected] = self._target_failure(selected)
                continue

            try:
                verified = verify(permanent)
            except _TERMINAL_FIREWALL_ERRORS:
                raise
            except (FirewallCommandError, FirewallParseError):
                verified = False

            results[selected] = (
                self._target_success(selected, command_result)
                if verified
                else self._target_failure(
                    selected, result=command_result, verification=True
                )
            )
        return self._composite(operation, results)

    def _apply_global(
        self,
        operation: str,
        target: ApplyTarget,
        spec: CommandSpec,
        verify: Callable[[], bool],
        sudo_password: str | None,
    ) -> CompositeOperationResult:
        self._require_global_target(target)
        selected_targets = (ApplyTarget.PERMANENT, ApplyTarget.RUNTIME)
        try:
            command_result = self._execute(spec, sudo_password)
        except _TERMINAL_FIREWALL_ERRORS:
            raise
        except FirewallCommandError:
            return self._composite(
                operation,
                {
                    selected: self._target_failure(selected)
                    for selected in selected_targets
                },
            )

        post_mutation_error: PostMutationVerificationError | None = None
        try:
            verified = verify()
        except (SudoAuthenticationError, SudoAuthenticationRequiredError):
            post_mutation_error = PostMutationVerificationError(
                self._server_id, operation
            )
        except _TERMINAL_FIREWALL_ERRORS:
            raise
        except (FirewallCommandError, FirewallParseError):
            verified = False

        if post_mutation_error is not None:
            raise post_mutation_error

        return self._composite(
            operation,
            {
                selected: (
                    self._target_success(selected, command_result)
                    if verified
                    else self._target_failure(
                        selected, result=command_result, verification=True
                    )
                )
                for selected in selected_targets
            },
        )

    def add_port(
        self,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        expected = FirewalldCommandBuilder.add_port(
            zone, port, protocol, permanent=False
        ).argv[-1].removeprefix("--add-port=")
        return self._apply_targets(
            "add_port",
            target,
            lambda permanent: FirewalldCommandBuilder.add_port(
                zone, port, protocol, permanent
            ),
            lambda permanent: expected
            in self.list_ports(
                zone, permanent=permanent, sudo_password=sudo_password
            ),
            sudo_password,
        )

    def remove_port(
        self,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        expected = FirewalldCommandBuilder.remove_port(
            zone, port, protocol, permanent=False
        ).argv[-1].removeprefix("--remove-port=")
        return self._apply_targets(
            "remove_port",
            target,
            lambda permanent: FirewalldCommandBuilder.remove_port(
                zone, port, protocol, permanent
            ),
            lambda permanent: expected
            not in self.list_ports(
                zone, permanent=permanent, sudo_password=sudo_password
            ),
            sudo_password,
        )

    def add_service(
        self,
        zone: str,
        service: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        return self._apply_targets(
            "add_service",
            target,
            lambda permanent: FirewalldCommandBuilder.add_service(
                zone, service, permanent
            ),
            lambda permanent: service
            in self.list_services(
                zone, permanent=permanent, sudo_password=sudo_password
            ),
            sudo_password,
        )

    def remove_service(
        self,
        zone: str,
        service: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        return self._apply_targets(
            "remove_service",
            target,
            lambda permanent: FirewalldCommandBuilder.remove_service(
                zone, service, permanent
            ),
            lambda permanent: service
            not in self.list_services(
                zone, permanent=permanent, sudo_password=sudo_password
            ),
            sudo_password,
        )

    def change_interface_zone(
        self,
        interface: str,
        zone: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        return self._apply_targets(
            "change_interface_zone",
            target,
            lambda permanent: FirewalldCommandBuilder.change_interface_zone(
                interface, zone, permanent
            ),
            lambda permanent: interface
            in self.get_interfaces(
                zone, permanent=permanent, sudo_password=sudo_password
            ),
            sudo_password,
        )

    def add_rich_rule(
        self,
        zone: str,
        source: str | None,
        destination: str | None,
        service: str | None,
        port: str | None,
        protocol: str | None,
        action: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        expected = FirewalldCommandBuilder.add_rich_rule(
            zone,
            source,
            destination,
            service,
            port,
            protocol,
            action,
            permanent=False,
        ).argv[-1].removeprefix("--add-rich-rule=")
        return self._apply_targets(
            "add_rich_rule",
            target,
            lambda permanent: FirewalldCommandBuilder.add_rich_rule(
                zone,
                source,
                destination,
                service,
                port,
                protocol,
                action,
                permanent,
            ),
            lambda permanent: expected
            in {
                rule.rule
                for rule in self.list_rich_rules(
                    zone, permanent=permanent, sudo_password=sudo_password
                )
            },
            sudo_password,
        )

    def remove_rich_rule(
        self,
        zone: str,
        source: str | None,
        destination: str | None,
        service: str | None,
        port: str | None,
        protocol: str | None,
        action: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        expected = FirewalldCommandBuilder.remove_rich_rule(
            zone,
            source,
            destination,
            service,
            port,
            protocol,
            action,
            permanent=False,
        ).argv[-1].removeprefix("--remove-rich-rule=")
        return self._apply_targets(
            "remove_rich_rule",
            target,
            lambda permanent: FirewalldCommandBuilder.remove_rich_rule(
                zone,
                source,
                destination,
                service,
                port,
                protocol,
                action,
                permanent,
            ),
            lambda permanent: expected
            not in {
                rule.rule
                for rule in self.list_rich_rules(
                    zone, permanent=permanent, sudo_password=sudo_password
                )
            },
            sudo_password,
        )

    def set_default_zone(
        self,
        zone: str,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self._require_global_target(target)

        def verify() -> bool:
            result = self._execute(
                FirewalldCommandBuilder.get_default_zone(), sudo_password
            )
            return self._single_word(result.stdout, "default zone") == zone

        return self._apply_global(
            "set_default_zone",
            target,
            FirewalldCommandBuilder.set_default_zone(zone),
            verify,
            sudo_password,
        )

    def reload_firewalld(
        self,
        target: ApplyTarget,
        *,
        sudo_password: str | None = None,
    ) -> CompositeOperationResult:
        self._require_global_target(target)

        def verify() -> bool:
            result = self._execute(FirewalldCommandBuilder.get_state(), sudo_password)
            return " ".join(parse_words(result.stdout)).casefold() == "running"

        return self._apply_global(
            "reload_firewalld",
            target,
            FirewalldCommandBuilder.reload(),
            verify,
            sudo_password,
        )
