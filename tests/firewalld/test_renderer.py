import pytest

from app.firewalld.renderer import render_command, render_sudo
from app.firewalld.system_commands import SystemCommandBuilder
from app.models.command import CommandSpec


def test_renderer_quotes_each_argument_as_one_linux_shell_word():
    spec = CommandSpec("probe", ("printf", "%s", "a value; id"), False)
    assert render_command(spec) == "printf %s 'a value; id'"


def test_renderer_preserves_argv_as_data_until_the_remote_shell_boundary():
    spec = CommandSpec("probe", ("echo", "$(id)", "quote'word"), False)
    assert render_command(spec) == "echo '$(id)' 'quote'\"'\"'word'"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("noninteractive", "sudo -n -- firewall-cmd --state"),
        ("stdin", "sudo -S -p '' -- firewall-cmd --state"),
    ],
)
def test_sudo_modes_have_exact_prefixes_without_a_password(mode, expected):
    spec = CommandSpec("state", ("firewall-cmd", "--state"), True)
    assert render_sudo(spec, mode) == expected


def test_sudo_rejects_unknown_modes():
    with pytest.raises(ValueError):
        render_sudo(CommandSpec("state", ("firewall-cmd", "--state")), "password=secret")


@pytest.mark.parametrize(
    ("builder", "operation", "argv"),
    [
        (SystemCommandBuilder.hostname, "hostname", ("hostname",)),
        (SystemCommandBuilder.distribution, "distribution", ("cat", "/etc/os-release")),
        (SystemCommandBuilder.effective_uid, "effective_uid", ("id", "-u")),
    ],
)
def test_system_probes_are_the_only_fixed_unprivileged_commands(builder, operation, argv):
    spec = builder()
    assert spec.operation == operation
    assert spec.argv == argv
    assert spec.requires_privilege is False
