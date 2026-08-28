from dataclasses import replace

import pytest

from app.config.config_manager import ConfigManager
from app.config.models import ApplicationConfig, LoadedConfig, ServerConfig
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
