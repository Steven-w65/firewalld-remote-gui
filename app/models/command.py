from dataclasses import dataclass
from typing import Literal

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


CompositeOutcome = Literal[
    "succeeded", "partial", "verification_failed", "failed", "inconsistent"
]


def classify_composite_outcome(result: CompositeOperationResult) -> CompositeOutcome:
    """Reduce target phase states to one fixed, credential-free outcome label."""
    if result.operation in {"reload_firewalld", "set_default_zone"} and (
        result.runtime is None or result.permanent is None
    ):
        return "inconsistent"
    phase_outcomes: list[str] = []
    for expected_target, target_result in (
        (ApplyTarget.RUNTIME, result.runtime),
        (ApplyTarget.PERMANENT, result.permanent),
    ):
        if target_result is None:
            continue
        if (
            not isinstance(target_result, TargetResult)
            or target_result.target is not expected_target
        ):
            return "inconsistent"
        phases = (
            target_result.execution_status,
            target_result.verification_status,
        )
        if phases == (TargetStatus.SUCCEEDED, TargetStatus.SUCCEEDED):
            phase_outcomes.append("succeeded")
        elif phases == (TargetStatus.SUCCEEDED, TargetStatus.FAILED):
            phase_outcomes.append("verification_failed")
        elif phases in (
            (TargetStatus.FAILED, TargetStatus.NOT_RUN),
            (TargetStatus.NOT_RUN, TargetStatus.NOT_RUN),
        ):
            phase_outcomes.append("failed")
        else:
            return "inconsistent"

    if not phase_outcomes:
        return "inconsistent"
    if all(outcome == "succeeded" for outcome in phase_outcomes):
        return "succeeded"
    if "succeeded" in phase_outcomes:
        return "partial"
    if "verification_failed" in phase_outcomes:
        return "verification_failed"
    return "failed"
