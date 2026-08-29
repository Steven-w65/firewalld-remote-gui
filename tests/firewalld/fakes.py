"""Strict offline fakes for the firewalld service boundary."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from app.models.command import CommandResult, CommandSpec


@dataclass(frozen=True, slots=True)
class ExecutedCommand:
    spec: CommandSpec
    sudo_password: str | None


@dataclass(frozen=True, slots=True)
class _ScriptedResponse:
    operation: str
    result: CommandResult | None = None
    error: BaseException | None = None


class ScriptedExecutor:
    """Return complete results in FIFO order and reject operation drift."""

    def __init__(self, server_id: str = "web01") -> None:
        self.server_id = server_id
        self._responses: deque[_ScriptedResponse] = deque()
        self.calls: list[ExecutedCommand] = []

    def respond(
        self,
        operation: str,
        *,
        exit_code: int = 0,
        stdout: str = "",
        stderr: str = "",
        success: bool | None = None,
        duration_seconds: float = 0.01,
    ) -> None:
        self._responses.append(
            _ScriptedResponse(
                operation,
                CommandResult(
                    success=exit_code == 0 if success is None else success,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr=stderr,
                    server_id=self.server_id,
                    operation=operation,
                    duration_seconds=duration_seconds,
                ),
            )
        )

    def raise_error(self, operation: str, error: BaseException) -> None:
        self._responses.append(_ScriptedResponse(operation, error=error))

    def execute_command(
        self,
        spec: CommandSpec,
        sudo_password: str | None = None,
    ) -> CommandResult:
        if not self._responses:
            raise AssertionError(f"Unexpected operation {spec.operation!r}; script is exhausted")
        scripted = self._responses.popleft()
        if spec.operation != scripted.operation:
            raise AssertionError(
                f"Expected operation {scripted.operation!r}, received {spec.operation!r}"
            )
        self.calls.append(ExecutedCommand(spec, sudo_password))
        if scripted.error is not None:
            raise scripted.error
        if scripted.result is None:
            raise AssertionError("Scripted response had neither a result nor an error")
        return scripted.result

    def assert_exhausted(self) -> None:
        if self._responses:
            operations = tuple(response.operation for response in self._responses)
            raise AssertionError(f"Unconsumed scripted operations: {operations!r}")


def zone_output(
    name: str,
    *,
    interfaces: str = "",
    services: str = "ssh",
    ports: str = "22/tcp",
    rich_rules: tuple[str, ...] = (),
) -> str:
    indented_rules = "".join(f"    {rule}\n" for rule in rich_rules)
    return (
        f"{name}\n"
        f"  interfaces: {interfaces}\n"
        "  sources:\n"
        f"  services: {services}\n"
        f"  ports: {ports}\n"
        "  protocols:\n"
        "  forward: no\n"
        "  masquerade: no\n"
        "  rich rules:\n"
        f"{indented_rules}"
    )


def install_standard_snapshot_script(executor: ScriptedExecutor) -> None:
    """Install the exact successful load_snapshot operation sequence."""
    executor.respond("hostname", stdout="web01.example.test\n")
    executor.respond(
        "distribution",
        stdout='NAME="Fedora Linux"\nPRETTY_NAME="Fedora Linux 42 (Server Edition)"\n',
    )
    executor.respond("get_state", stdout="running\n")
    executor.respond("get_version", stdout="2.3.1\n")
    executor.respond("get_default_zone", stdout="public\n")
    executor.respond(
        "list_active_zones",
        stdout="public\n  interfaces: eth0\ninternal\n  interfaces: eth1\n",
    )
    executor.respond("list_zones_runtime", stdout="public internal\n")
    executor.respond(
        "get_zone_details_runtime",
        stdout=zone_output(
            "public",
            services="ssh http",
            ports="22/tcp 8080/tcp",
            rich_rules=(
                'rule family="ipv4" source address="192.0.2.0/24" service name="ssh" accept',
            ),
        ),
    )
    executor.respond(
        "get_zone_details_runtime",
        stdout=zone_output("internal", services="dns", ports="53/udp"),
    )
    executor.respond("list_zones_permanent", stdout="public\n")
    executor.respond(
        "get_zone_details_permanent",
        stdout=zone_output("public", services="ssh", ports="22/tcp"),
    )
    executor.respond("list_available_services", stdout="ssh http https dns\n")
