from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class ServerConfig:
    id: str
    name: str
    host: str
    username: str
    password: str = field(repr=False)
    port: int = 22
    sudo: bool = False
    connect_timeout: float | None = None
    command_timeout: float | None = None


@dataclass(frozen=True, slots=True)
class ApplicationConfig:
    ssh_timeout: float = 10.0
    command_timeout: float = 20.0
    confirm_changes: bool = True
    strict_host_key_checking: bool = True


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    application: ApplicationConfig
    servers: tuple[ServerConfig, ...]


@dataclass(frozen=True, slots=True)
class ConfigDiff:
    unchanged: tuple[str, ...]
    changed: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]
