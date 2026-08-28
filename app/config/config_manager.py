from collections.abc import Mapping
from pathlib import Path

import yaml

from app.config.models import ApplicationConfig, ConfigDiff, LoadedConfig, ServerConfig
from app.utils.errors import ConfigurationError


class ConfigManager:
    _APPLICATION_FIELDS = {"ssh_timeout", "command_timeout", "confirm_changes", "strict_host_key_checking"}
    _SERVER_FIELDS = {"id", "name", "host", "username", "password", "port", "sudo", "connect_timeout", "command_timeout"}
    _REQUIRED_SERVER_FIELDS = {"id", "name", "host", "username", "password"}

    def __init__(self, path: Path):
        self._path = path

    def load(self) -> LoadedConfig:
        try:
            data = yaml.safe_load(self._path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            raise ConfigurationError("unable to read configuration") from error
        if not isinstance(data, Mapping):
            raise ConfigurationError("configuration must be a mapping")
        self._reject_unknown(data, {"application", "servers"}, "configuration")
        if "servers" not in data:
            raise ConfigurationError("missing required field: servers")
        servers_data = data["servers"]
        if not isinstance(servers_data, list):
            raise ConfigurationError("servers must be a list")
        application = self._application(data.get("application", {}))
        servers = tuple(self._server(item, index) for index, item in enumerate(servers_data))
        ids = [server.id for server in servers]
        if len(ids) != len(set(ids)):
            raise ConfigurationError("duplicate server id")
        return LoadedConfig(application, servers)

    @classmethod
    def diff(cls, old: LoadedConfig, new: LoadedConfig) -> ConfigDiff:
        old_by_id = {server.id: server for server in old.servers}
        new_by_id = {server.id: server for server in new.servers}
        unchanged = tuple(server.id for server in new.servers if server.id in old_by_id and old_by_id[server.id] == server)
        changed = tuple(server.id for server in new.servers if server.id in old_by_id and old_by_id[server.id] != server)
        added = tuple(server.id for server in new.servers if server.id not in old_by_id)
        removed = tuple(server.id for server in old.servers if server.id not in new_by_id)
        return ConfigDiff(unchanged, changed, added, removed)

    def _application(self, data: object) -> ApplicationConfig:
        if not isinstance(data, Mapping):
            raise ConfigurationError("application must be a mapping")
        self._reject_unknown(data, self._APPLICATION_FIELDS, "application")
        ssh_timeout = self._timeout(data.get("ssh_timeout", 10.0), "application.ssh_timeout")
        command_timeout = self._timeout(data.get("command_timeout", 20.0), "application.command_timeout")
        confirm_changes = self._boolean(data.get("confirm_changes", True), "application.confirm_changes")
        strict_host_key_checking = self._boolean(data.get("strict_host_key_checking", True), "application.strict_host_key_checking")
        return ApplicationConfig(ssh_timeout, command_timeout, confirm_changes, strict_host_key_checking)

    def _server(self, data: object, index: int) -> ServerConfig:
        path = f"servers[{index}]"
        if not isinstance(data, Mapping):
            raise ConfigurationError(f"{path} must be a mapping")
        self._reject_unknown(data, self._SERVER_FIELDS, path)
        for field in self._REQUIRED_SERVER_FIELDS:
            if field not in data:
                raise ConfigurationError(f"{path}.{field}: missing required field")
            if not isinstance(data[field], str) or not data[field]:
                raise ConfigurationError(f"{path}.{field} must be a non-empty string")
        port = data.get("port", 22)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ConfigurationError(f"{path}.port must be an integer from 1 to 65535")
        sudo = self._boolean(data.get("sudo", False), f"{path}.sudo")
        connect_timeout = self._optional_timeout(data.get("connect_timeout"), f"{path}.connect_timeout")
        command_timeout = self._optional_timeout(data.get("command_timeout"), f"{path}.command_timeout")
        return ServerConfig(data["id"], data["name"], data["host"], data["username"], data["password"], port, sudo, connect_timeout, command_timeout)

    @staticmethod
    def _reject_unknown(data: Mapping, allowed: set[str], path: str) -> None:
        for field in data:
            if field not in allowed:
                raise ConfigurationError(f"{path}.{field}: unknown field")

    @staticmethod
    def _boolean(value: object, path: str) -> bool:
        if not isinstance(value, bool):
            raise ConfigurationError(f"{path} must be a boolean")
        return value

    @staticmethod
    def _timeout(value: object, path: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ConfigurationError(f"{path} must be a positive number")
        return float(value)

    @classmethod
    def _optional_timeout(cls, value: object, path: str) -> float | None:
        return None if value is None else cls._timeout(value, path)
