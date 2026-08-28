import re
import traceback
from dataclasses import replace

import pytest

from app.config.config_manager import ConfigManager
from app.config.models import ApplicationConfig, ConfigDiff, LoadedConfig, ServerConfig
from app.utils.errors import ConfigurationError


def write_config(path, body):
    path.write_text(body, encoding="utf-8")


def test_loads_multiple_servers_with_defaults(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(
        path,
        "servers:\n"
        "  - id: web01\n    name: Web\n    host: 192.0.2.10\n"
        "    username: admin\n    password: secret\n"
        "  - id: db01\n    name: DB\n    host: db.example\n"
        "    username: root\n    password: other\n    port: 2222\n",
    )

    loaded = ConfigManager(path).load()

    assert [server.id for server in loaded.servers] == ["web01", "db01"]
    assert loaded.servers[0].port == 22
    assert loaded.servers[1].port == 2222
    assert loaded.application == ApplicationConfig()


@pytest.mark.parametrize(
    "body, message",
    [
        ("servers: [{id: web01}]", "missing required field"),
        ("servers: []\nunknown: true", "unknown field"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p, port: 0}]", r"servers\[0\]\.port"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p, port: true}]", r"servers\[0\]\.port"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p, sudo_password: x}]", "sudo_password"),
        ("application: {ssh_timeout: 0}\nservers: []", "application.ssh_timeout"),
        ("application: {confirm_changes: 1}\nservers: []", "application.confirm_changes"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p, sudo: 1}]", r"servers\[0\]\.sudo"),
        ("servers: [{id: a, name: A, host: h, username: u, password: p}, {id: a, name: B, host: h2, username: u, password: p}]", "duplicate server id"),
    ],
)
def test_rejects_invalid_configuration(tmp_path, body, message):
    path = tmp_path / "config.yaml"
    write_config(path, body)

    with pytest.raises(ConfigurationError, match=message):
        ConfigManager(path).load()


def test_rejects_unknown_server_and_application_keys(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(
        path,
        "application: {unexpected: true}\n"
        "servers: [{id: a, name: A, host: h, username: u, password: p, extra: x}]",
    )

    with pytest.raises(ConfigurationError, match="application.unexpected"):
        ConfigManager(path).load()


def test_configuration_errors_never_echo_password_values(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "servers: [{id: a, name: A, host: h, username: u, password: top-secret, sudo_password: do-not-echo}]")

    with pytest.raises(ConfigurationError) as error:
        ConfigManager(path).load()

    assert "top-secret" not in str(error.value)
    assert "do-not-echo" not in str(error.value)


def test_malformed_yaml_traceback_never_echoes_password_values(tmp_path):
    path = tmp_path / "config.yaml"
    password = "malformed-yaml-password"
    write_config(
        path,
        "servers:\n"
        "  - id: a\n"
        "    name: A\n"
        "    host: h\n"
        "    username: u\n"
        f'    password: "{password}\n',
    )

    with pytest.raises(ConfigurationError) as error:
        ConfigManager(path).load()

    rendered = "".join(traceback.format_exception(error.type, error.value, error.tb))
    assert password not in rendered


_OVERFLOWING_TIMEOUT = "1" + ("0" * 400)
_INVALID_TIMEOUTS = ("0", "true", ".nan", ".inf", _OVERFLOWING_TIMEOUT)


@pytest.mark.parametrize("field", ("ssh_timeout", "command_timeout"))
@pytest.mark.parametrize("value", _INVALID_TIMEOUTS)
def test_rejects_invalid_application_timeouts_with_safe_path_error(
    tmp_path,
    field,
    value,
):
    path = tmp_path / "config.yaml"
    write_config(path, f"application: {{{field}: {value}}}\nservers: []")

    with pytest.raises(
        ConfigurationError,
        match=re.escape(f"application.{field}"),
    ) as error:
        ConfigManager(path).load()

    assert str(error.value) == f"application.{field} must be a positive number"


@pytest.mark.parametrize("field", ("connect_timeout", "command_timeout"))
@pytest.mark.parametrize("value", _INVALID_TIMEOUTS)
def test_rejects_invalid_server_timeouts_with_safe_path_error(
    tmp_path,
    field,
    value,
):
    path = tmp_path / "config.yaml"
    write_config(
        path,
        "servers:\n"
        "  - {id: a, name: A, host: h, username: u, password: p, "
        f"{field}: {value}}}",
    )

    with pytest.raises(
        ConfigurationError,
        match=re.escape(f"servers[0].{field}"),
    ) as error:
        ConfigManager(path).load()

    assert str(error.value) == f"servers[0].{field} must be a positive number"


def test_diff_classifies_all_server_categories():
    unchanged = ServerConfig("same", "Same", "192.0.2.1", "u", "p")
    changed_old = ServerConfig("changed", "Old", "192.0.2.2", "u", "p")
    changed_new = replace(changed_old, name="New")
    old = LoadedConfig(ApplicationConfig(), (unchanged, changed_old, ServerConfig("removed", "Removed", "192.0.2.3", "u", "p")))
    new = LoadedConfig(ApplicationConfig(), (unchanged, changed_new, ServerConfig("added", "Added", "192.0.2.4", "u", "p")))

    diff = ConfigManager.diff(old, new)

    assert diff.unchanged == ("same",)
    assert diff.changed == ("changed",)
    assert diff.added == ("added",)
    assert diff.removed == ("removed",)


def test_loaded_config_copies_a_mutable_server_collection():
    servers = [ServerConfig("server-a", "A", "192.0.2.1", "u", "p")]

    loaded = LoadedConfig(ApplicationConfig(), servers)
    servers.append(ServerConfig("server-b", "B", "192.0.2.2", "u", "p"))

    assert loaded.servers == (ServerConfig("server-a", "A", "192.0.2.1", "u", "p"),)
    assert isinstance(loaded.servers, tuple)


def test_config_diff_copies_mutable_category_collections():
    unchanged = ["same"]
    changed = ["changed"]
    added = ["added"]
    removed = ["removed"]

    diff = ConfigDiff(unchanged, changed, added, removed)
    unchanged.append("later")
    changed.append("later")
    added.append("later")
    removed.append("later")

    assert diff == ConfigDiff(("same",), ("changed",), ("added",), ("removed",))
    assert all(
        isinstance(category, tuple)
        for category in (diff.unchanged, diff.changed, diff.added, diff.removed)
    )
