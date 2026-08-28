from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PortablePaths:
    root: Path
    config_file: Path
    known_hosts_file: Path
    log_dir: Path

    @classmethod
    def from_entrypoint(cls, entrypoint: Path) -> "PortablePaths":
        root = entrypoint.resolve().parent
        return cls(
            root=root,
            config_file=root / "config.yaml",
            known_hosts_file=root / "known_hosts",
            log_dir=root / "logs",
        )
