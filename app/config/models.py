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

    def __post_init__(self) -> None:
        object.__setattr__(self, "servers", tuple(self.servers))


@dataclass(frozen=True, slots=True)
class ConfigDiff:
    unchanged: tuple[str, ...]
    changed: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "unchanged", tuple(self.unchanged))
        object.__setattr__(self, "changed", tuple(self.changed))
        object.__setattr__(self, "added", tuple(self.added))
        object.__setattr__(self, "removed", tuple(self.removed))
