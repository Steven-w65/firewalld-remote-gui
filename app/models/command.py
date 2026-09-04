from dataclasses import dataclass

from .enums import ApplyTarget, TargetStatus


@dataclass(frozen=True, slots=True)
class CommandSpec:
    operation: str
    argv: tuple[str, ...]
    requires_privilege: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv", tuple(self.argv))


@dataclass(frozen=True, slots=True)
class CommandResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    server_id: str
    operation: str
    duration_seconds: float


@dataclass(frozen=True, slots=True)
class TargetResult:
    target: ApplyTarget
    execution_status: TargetStatus
    verification_status: TargetStatus
    result: CommandResult | None
    message: str
    authentication_failed: bool = False

    @property
    def is_success(self) -> bool:
        return (
            self.execution_status is TargetStatus.SUCCEEDED
            and self.verification_status is TargetStatus.SUCCEEDED
        )


@dataclass(frozen=True, slots=True)
class CompositeOperationResult:
    operation: str
    runtime: TargetResult | None = None
    permanent: TargetResult | None = None

    @property
    def is_success(self) -> bool:
        targets = tuple(result for result in (self.runtime, self.permanent) if result is not None)
        return bool(targets) and all(result.is_success for result in targets)

    @property
    def is_partial(self) -> bool:
        targets = tuple(result for result in (self.runtime, self.permanent) if result is not None)
        return any(result.is_success for result in targets) and any(not result.is_success for result in targets)
