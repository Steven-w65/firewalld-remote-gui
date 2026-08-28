class ConfigurationError(ValueError):
    """Raised when the portable configuration is invalid."""


class InvalidFirewallArgumentError(ValueError):
    """Raised when a firewall operation argument fails strict validation."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid {field}: {reason}")
