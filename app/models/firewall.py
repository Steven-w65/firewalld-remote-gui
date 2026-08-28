from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class FirewallPort:
    port: str
    protocol: str
    zone: str
    runtime: bool
    permanent: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "protocol", self.protocol.lower())


@dataclass(frozen=True, slots=True)
class InterfaceAssignment:
    interface: str
    zone: str
    runtime: bool
    permanent: bool


@dataclass(frozen=True, slots=True)
class RichRule:
    rule: str
    source: str | None = None
    destination: str | None = None
    service: str | None = None
    port: str | None = None
    protocol: str | None = None
    action: str | None = None

    def __post_init__(self) -> None:
        if self.protocol is not None:
            object.__setattr__(self, "protocol", self.protocol.lower())


@dataclass(frozen=True, slots=True)
class ZoneState:
    name: str
    interfaces: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    ports: tuple[FirewallPort, ...] = ()
    rich_rules: tuple[RichRule, ...] = ()
    masquerade: bool = False
    forwarding: bool = False


@dataclass(frozen=True, slots=True)
class FirewallSnapshot:
    hostname: str
    distribution: str
    firewalld_running: bool
    firewalld_version: str | None
    default_zone: str
    runtime_zones: tuple[ZoneState, ...] = field(default_factory=tuple)
    permanent_zones: tuple[ZoneState, ...] = field(default_factory=tuple)
    available_services: tuple[str, ...] = field(default_factory=tuple)
    stale: bool = False

    def zone(self, name: str, permanent: bool) -> ZoneState | None:
        zones = self.permanent_zones if permanent else self.runtime_zones
        return next((zone for zone in zones if zone.name == name), None)

    def has_port(self, zone: str, port: str, protocol: str, permanent: bool) -> bool:
        state = self.zone(zone, permanent)
        if state is None:
            return False
        normalized_protocol = protocol.lower()
        return any(item.port == port and item.protocol == normalized_protocol for item in state.ports)
