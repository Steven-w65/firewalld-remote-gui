"""Build the complete allowlisted ``firewall-cmd`` command surface."""

from __future__ import annotations

from app.models.command import CommandSpec
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import (
    validate_inventory_token,
    validate_ip_network,
    validate_port,
    validate_protocol,
    validate_rich_action,
)


class FirewalldCommandBuilder:
    """Construct deterministic command specifications from safe structured values."""

    @staticmethod
    def _spec(operation: str, arguments: tuple[str, ...], permanent: bool = False) -> CommandSpec:
        prefix = ("firewall-cmd", "--permanent") if permanent else ("firewall-cmd",)
        suffix = "_permanent" if permanent else "_runtime"
        return CommandSpec(f"{operation}{suffix}", (*prefix, *arguments))

    @staticmethod
    def _zone(value: str) -> str:
        return validate_inventory_token("zone", value)

    @staticmethod
    def _service(value: str) -> str:
        return validate_inventory_token("service", value)

    @staticmethod
    def _interface(value: str) -> str:
        return validate_inventory_token("interface", value)

    @staticmethod
    def get_state() -> CommandSpec:
        return CommandSpec("get_state", ("firewall-cmd", "--state"))

    @staticmethod
    def get_version() -> CommandSpec:
        return CommandSpec("get_version", ("firewall-cmd", "--version"))

    @classmethod
    def list_zones(cls, permanent: bool = False) -> CommandSpec:
        return cls._spec("list_zones", ("--get-zones",), permanent)

    @staticmethod
    def list_active_zones() -> CommandSpec:
        return CommandSpec("list_active_zones", ("firewall-cmd", "--get-active-zones"))

    @classmethod
    def get_default_zone(cls, permanent: bool = False) -> CommandSpec:
        return cls._spec("get_default_zone", ("--get-default-zone",), permanent)

    @classmethod
    def set_default_zone(cls, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec("set_default_zone", (f"--set-default-zone={cls._zone(zone)}",), permanent)

    @classmethod
    def get_zone_details(cls, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec("get_zone_details", (f"--zone={cls._zone(zone)}", "--list-all"), permanent)

    @classmethod
    def list_ports(cls, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec("list_ports", (f"--zone={cls._zone(zone)}", "--list-ports"), permanent)

    @classmethod
    def add_port(cls, zone: str, port: str, protocol: str, permanent: bool = False) -> CommandSpec:
        return cls._port_change("add_port", "--add-port", zone, port, protocol, permanent)

    @classmethod
    def remove_port(cls, zone: str, port: str, protocol: str, permanent: bool = False) -> CommandSpec:
        return cls._port_change("remove_port", "--remove-port", zone, port, protocol, permanent)

    @classmethod
    def _port_change(
        cls, operation: str, option: str, zone: str, port: str, protocol: str, permanent: bool
    ) -> CommandSpec:
        return cls._spec(
            operation,
            (f"--zone={cls._zone(zone)}", f"{option}={validate_port(port)}/{validate_protocol(protocol)}"),
            permanent,
        )

    @staticmethod
    def list_available_services() -> CommandSpec:
        return CommandSpec("list_available_services", ("firewall-cmd", "--get-services"))

    @classmethod
    def list_services(cls, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec("list_services", (f"--zone={cls._zone(zone)}", "--list-services"), permanent)

    @classmethod
    def add_service(cls, zone: str, service: str, permanent: bool = False) -> CommandSpec:
        return cls._service_change("add_service", "--add-service", zone, service, permanent)

    @classmethod
    def remove_service(cls, zone: str, service: str, permanent: bool = False) -> CommandSpec:
        return cls._service_change("remove_service", "--remove-service", zone, service, permanent)

    @classmethod
    def _service_change(
        cls, operation: str, option: str, zone: str, service: str, permanent: bool
    ) -> CommandSpec:
        return cls._spec(operation, (f"--zone={cls._zone(zone)}", f"{option}={cls._service(service)}"), permanent)

    @classmethod
    def list_interfaces(cls, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec("list_interfaces", (f"--zone={cls._zone(zone)}", "--list-interfaces"), permanent)

    @classmethod
    def change_interface_zone(cls, interface: str, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec(
            "change_interface_zone",
            (f"--zone={cls._zone(zone)}", f"--change-interface={cls._interface(interface)}"),
            permanent,
        )

    @classmethod
    def list_rich_rules(cls, zone: str, permanent: bool = False) -> CommandSpec:
        return cls._spec("list_rich_rules", (f"--zone={cls._zone(zone)}", "--list-rich-rules"), permanent)

    @classmethod
    def add_rich_rule(
        cls,
        zone: str,
        source: str | None,
        destination: str | None,
        service: str | None,
        port: str | None,
        protocol: str | None,
        action: str,
        permanent: bool = False,
    ) -> CommandSpec:
        rule = cls._rich_rule(source, destination, service, port, protocol, action)
        return cls._spec("add_rich_rule", (f"--zone={cls._zone(zone)}", f"--add-rich-rule={rule}"), permanent)

    @classmethod
    def remove_rich_rule(
        cls,
        zone: str,
        source: str | None,
        destination: str | None,
        service: str | None,
        port: str | None,
        protocol: str | None,
        action: str,
        permanent: bool = False,
    ) -> CommandSpec:
        rule = cls._rich_rule(source, destination, service, port, protocol, action)
        return cls._spec("remove_rich_rule", (f"--zone={cls._zone(zone)}", f"--remove-rich-rule={rule}"), permanent)

    @classmethod
    def _rich_rule(
        cls,
        source: str | None,
        destination: str | None,
        service: str | None,
        port: str | None,
        protocol: str | None,
        action: str,
    ) -> str:
        if (service is None) == (port is None):
            raise InvalidFirewallArgumentError("rich rule", "requires exactly one of service or port")
        if service is not None and protocol is not None:
            raise InvalidFirewallArgumentError("rich rule", "does not allow protocol with a service")
        if port is not None and protocol is None:
            raise InvalidFirewallArgumentError("rich rule", "requires protocol with a port")
        normalized_source = validate_ip_network(source) if source is not None else None
        normalized_destination = validate_ip_network(destination) if destination is not None else None
        addresses = tuple(value for value in (normalized_source, normalized_destination) if value is not None)
        if not addresses:
            raise InvalidFirewallArgumentError("rich rule", "requires a source or destination network")
        families = {":" in value for value in addresses}
        if len(families) != 1:
            raise InvalidFirewallArgumentError("rich rule", "source and destination must use the same address family")
        family = "ipv6" if families.pop() else "ipv4"

        clauses = [f'rule family="{family}"']
        if normalized_source is not None:
            clauses.append(f'source address="{normalized_source}"')
        if normalized_destination is not None:
            clauses.append(f'destination address="{normalized_destination}"')
        if service is not None:
            clauses.append(f'service name="{cls._service(service)}"')
        else:
            clauses.append(f'port port="{validate_port(port)}" protocol="{validate_protocol(protocol)}"')
        clauses.append(validate_rich_action(action))
        return " ".join(clauses)

    @staticmethod
    def reload() -> CommandSpec:
        return CommandSpec("reload", ("firewall-cmd", "--reload"))
