"""Fixed, unprivileged system probes used during connection checks."""

from __future__ import annotations

from app.models.command import CommandSpec


class SystemCommandBuilder:
    """Construct the small, closed set of safe connection probes."""

    @staticmethod
    def hostname() -> CommandSpec:
        return CommandSpec("hostname", ("hostname",), requires_privilege=False)

    @staticmethod
    def distribution() -> CommandSpec:
        return CommandSpec("distribution", ("cat", "/etc/os-release"), requires_privilege=False)

    @staticmethod
    def effective_uid() -> CommandSpec:
        return CommandSpec("effective_uid", ("id", "-u"), requires_privilege=False)
