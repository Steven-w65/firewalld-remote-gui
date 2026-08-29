"""Read-only remote firewalld service assembled from approved commands."""

from __future__ import annotations

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
from app.models.command import CommandResult, CommandSpec
from app.models.firewall import FirewallSnapshot, RichRule, ZoneState
from app.utils.errors import (
    FirewallCommandError,
    FirewallParseError,
    FirewalldNotInstalledError,
    FirewalldNotRunningError,
    InvalidFirewallArgumentError,
    PermissionDeniedError,
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
    firewalld: FirewalldInfo
    checks: tuple[ConnectionCheck, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "checks", tuple(self.checks))


_FAILURE_MARKERS: tuple[
    tuple[type[FirewallCommandError], tuple[str, ...]], ...
] = (
    (
        FirewalldNotInstalledError,
        ("command not found", "firewall-cmd: not found", "no such file or directory"),
    ),
    (FirewalldNotRunningError, ("firewalld is not running", "firewalld not running")),
    (
        PermissionDeniedError,
        ("permission denied", "not authorized", "authorization failed"),
    ),
    (
        UnsupportedFirewalldFeatureError,
        ("unrecognized arguments", "unknown option", "invalid option", "not a valid option"),
    ),
)

_PARTIAL_READ_ERRORS = (FirewallCommandError, FirewallParseError)


class FirewalldService:
    """Execute only allowlisted read commands through an injected executor."""

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
            raise FirewallCommandError(self._server_id, spec.operation)
        if result.success and result.exit_code == 0:
            return result
        self._raise_classified(spec.operation, result)
        raise AssertionError("unreachable")

    def _raise_classified(self, operation: str, result: CommandResult) -> None:
        output = f"{result.stdout}\n{result.stderr}".casefold()
        for error_type, markers in _FAILURE_MARKERS:
            if any(marker in output for marker in markers):
                raise error_type(self._server_id, operation)
        raise FirewallCommandError(self._server_id, operation)

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
        version_result = self._execute(
            FirewalldCommandBuilder.get_version(), sudo_password
        )
        version = self._single_word(version_result.stdout, "firewalld version")
        return FirewalldInfo(installed=True, running=True, version=version)

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
        except _PARTIAL_READ_ERRORS:
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
        except _PARTIAL_READ_ERRORS:
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
        except _PARTIAL_READ_ERRORS:
            effective_uid = None
            checks.append(
                ConnectionCheck(
                    "effective_uid", False, "Unable to read remote effective UID."
                )
            )

        try:
            firewalld = self.detect(sudo_password=sudo_password)
            if not firewalld.installed:
                firewalld_message = "Firewalld is not installed."
            elif not firewalld.running:
                firewalld_message = "Firewalld is not running."
            else:
                firewalld_message = "Firewalld is running."
            checks.append(
                ConnectionCheck(
                    "firewalld", firewalld.running, firewalld_message
                )
            )
        except _PARTIAL_READ_ERRORS:
            firewalld = FirewalldInfo(installed=True, running=False, version=None)
            checks.append(
                ConnectionCheck("firewalld", False, "Unable to inspect firewalld.")
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
        except _PARTIAL_READ_ERRORS:
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
        except _PARTIAL_READ_ERRORS:
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
        except _PARTIAL_READ_ERRORS:
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
            except (
                FirewallCommandError,
                FirewallParseError,
                InvalidFirewallArgumentError,
            ):
                stale = True
        return tuple(zones), stale
