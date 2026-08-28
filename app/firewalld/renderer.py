"""Render validated command argument vectors for the remote POSIX shell."""

from __future__ import annotations

import shlex
from typing import Literal

from app.models.command import CommandSpec


def render_command(spec: CommandSpec) -> str:
    """Render an approved argv tuple with POSIX-shell quoting."""
    return shlex.join(spec.argv)


def render_sudo(spec: CommandSpec, mode: Literal["noninteractive", "stdin"]) -> str:
    """Render an approved command with one of the two password-free sudo forms."""
    if mode == "noninteractive":
        prefix = ("sudo", "-n", "--")
    elif mode == "stdin":
        prefix = ("sudo", "-S", "-p", "", "--")
    else:
        raise ValueError("sudo mode must be 'noninteractive' or 'stdin'")
    return shlex.join((*prefix, *spec.argv))
