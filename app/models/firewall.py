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
    family: str | None = None

    def __post_init__(self) -> None:
        if self.family is not None:
            object.__setattr__(self, "family", self.family.lower())
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
    permanent: bool = False
    protocols: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "interfaces", tuple(self.interfaces))
        object.__setattr__(self, "sources", tuple(self.sources))
        object.__setattr__(self, "services", tuple(self.services))
        object.__setattr__(self, "ports", tuple(self.ports))
        object.__setattr__(self, "rich_rules", tuple(self.rich_rules))
        object.__setattr__(self, "protocols", tuple(self.protocols))


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

    def __post_init__(self) -> None:
        object.__setattr__(self, "runtime_zones", tuple(self.runtime_zones))
        object.__setattr__(self, "permanent_zones", tuple(self.permanent_zones))
        object.__setattr__(self, "available_services", tuple(self.available_services))

    def zone(self, name: str, permanent: bool) -> ZoneState | None:
        zones = self.permanent_zones if permanent else self.runtime_zones
        return next((zone for zone in zones if zone.name == name), None)

    def has_port(self, zone: str, port: str, protocol: str, permanent: bool) -> bool:
        state = self.zone(zone, permanent)
        if state is None:
            return False
        normalized_protocol = protocol.lower()
        return any(item.port == port and item.protocol == normalized_protocol for item in state.ports)
