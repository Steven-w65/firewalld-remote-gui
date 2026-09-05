"""Validated, confirmed firewall intentions over frozen server state."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial

from PySide6.QtCore import QObject, Signal

from app.controllers.server_controller import (
    ControllerJobHandle,
    ControllerOperationError,
    ServerController,
)
from app.controllers.session import ServerSessionView
from app.firewalld.lockout import (
    LockoutRisk,
    RemovePortChange,
    RemoveServiceChange,
    RiskLevel,
    assess_lockout_risk,
)
from app.models.change import ChangePreview
from app.models.command import CompositeOperationResult, TargetResult
from app.models.enums import ApplyTarget, ConnectionStatus, TargetStatus
from app.models.firewall import FirewallSnapshot
from app.models.interface import ChangeInterfaceRequest
from app.models.port import AddPortRequest, PortRow
from app.models.service import AddServiceRequest, ServiceRow
from app.utils.errors import InvalidFirewallArgumentError
from app.utils.validation import validate_inventory_value


_INCOMPLETE_ADD_RISK = LockoutRisk(
    RiskLevel.NONE,
    (
        "No recognized SSH lockout risk was found for this addition. Detection "
        "is incomplete and does not guarantee that a firewall change is safe.",
    ),
)

_DEFAULT_ZONE_RISK = LockoutRisk(
    RiskLevel.NONE,
    (
        "Changing the default zone affects traffic that is not assigned to another "
        "zone. Review the destination zone before applying this global change.",
    ),
)

_INACTIVE_INTERFACE_RISK = LockoutRisk(
    RiskLevel.NONE,
    ("The selected interface is not active in the current runtime snapshot.",),
)


def _active_interface_risk(management_port: int) -> LockoutRisk:
    return LockoutRisk(
        RiskLevel.HIGH,
        (
            "This is an active interface. Changing its zone may interrupt SSH "
            f"access on management port {management_port} because the client "
            "cannot reliably identify the SSH route's egress interface.",
        ),
    )


class FirewallJobHandle(QObject):
    """GUI-owned, credential-free facade for one logical confirmed change."""

    started = Signal(str, int, str)
    succeeded = Signal(str, int, str, object)
    failed = Signal(str, int, str, object)
    finished = Signal(str, int, str)

    def __init__(self, server_id: str, generation: int, operation: str) -> None:
        super().__init__()
        self.server_id = server_id
        self.generation = generation
        self.operation = operation


@dataclass(slots=True)
class _PendingFirewallIntent:
    server_id: str
    generation: int
    operation: str
    facade: FirewallJobHandle
    internal: ControllerJobHandle
    outcome_emitted: bool = False
    error_emitted: bool = False


class FirewallController(QObject):
    """Validate snapshots, schedule typed firewall writes, and publish safe outcomes."""

    operation_result = Signal(str, object)
    snapshot_changed = Signal(str, object)
    error_raised = Signal(str, object)

    def __init__(self, server_controller: ServerController) -> None:
        super().__init__()
        self.server_controller = server_controller
        self._pending: dict[tuple[str, int, str], _PendingFirewallIntent] = {}
        server_controller.error_raised.connect(self._forward_matching_error)

    def preview_add_port(
        self, server_id: str, request: AddPortRequest
    ) -> ChangePreview:
        if not isinstance(request, AddPortRequest):
            raise TypeError("request must be an AddPortRequest")
        view, snapshot = self._actionable_snapshot(server_id, "add a port")
        self._require_target_zones(snapshot, request.zone, request.target)
        for permanent in self._target_permanence(request.target):
            if snapshot.has_port(
                request.zone, request.port, request.protocol, permanent
            ):
                raise ValueError("The port already exists in a requested target.")
        return ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Add Firewall Port",
            zone=request.zone,
            resource=f"{request.port}/{request.protocol}",
            target=request.target,
            risk=_INCOMPLETE_ADD_RISK,
            server_id=view.server_id,
            generation=view.generation,
        )

    def preview_remove_port(
        self,
        server_id: str,
        row: PortRow,
        target: ApplyTarget,
    ) -> ChangePreview:
        if not isinstance(row, PortRow):
            raise TypeError("row must be a PortRow")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        view, snapshot = self._actionable_snapshot(server_id, "remove a port")
        self._require_target_zones(snapshot, row.zone, target)
        runtime = snapshot.has_port(row.zone, row.port, row.protocol, False)
        permanent = snapshot.has_port(row.zone, row.port, row.protocol, True)
        if row.runtime != runtime or row.permanent != permanent:
            raise ValueError("The selected port row changed in the current snapshot.")
        for target_permanent in self._target_permanence(target):
            if not (permanent if target_permanent else runtime):
                raise ValueError("The port is absent from a requested remove target.")
        risk = assess_lockout_risk(
            RemovePortChange(row.zone, row.port, row.protocol),
            snapshot,
            ssh_port=view.port,
        )
        return ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Remove Firewall Port",
            zone=row.zone,
            resource=f"{row.port}/{row.protocol}",
            target=target,
            risk=risk,
            server_id=view.server_id,
            generation=view.generation,
        )

    def preview_set_default_zone(
        self, server_id: str, new_zone: str
    ) -> ChangePreview:
        view, snapshot = self._actionable_snapshot(
            server_id, "change the default zone"
        )
        available = tuple(
            dict.fromkeys(
                zone.name
                for zone in snapshot.runtime_zones + snapshot.permanent_zones
            )
        )
        validated = validate_inventory_value("zone", new_zone, available)
        if validated == snapshot.default_zone:
            raise InvalidFirewallArgumentError(
                "zone", "must differ from the current default zone"
            )
        return ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Set Default Zone",
            zone="Global",
            resource=f"{snapshot.default_zone} → {validated}",
            target=ApplyTarget.BOTH,
            risk=_DEFAULT_ZONE_RISK,
            server_id=view.server_id,
            generation=view.generation,
        )

    def preview_add_service(
        self, server_id: str, request: AddServiceRequest
    ) -> ChangePreview:
        if not isinstance(request, AddServiceRequest):
            raise TypeError("request must be an AddServiceRequest")
        view, snapshot = self._actionable_snapshot(server_id, "add a service")
        self._require_target_zones(snapshot, request.zone, request.target)
        validate_inventory_value(
            "service", request.service, snapshot.available_services
        )
        if all(
            snapshot.has_service(request.zone, request.service, permanent)
            for permanent in self._target_permanence(request.target)
        ):
            raise ValueError("The service already exists in every requested target.")
        return ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Add Firewall Service",
            zone=request.zone,
            resource=request.service,
            target=request.target,
            risk=_INCOMPLETE_ADD_RISK,
            server_id=view.server_id,
            generation=view.generation,
        )

    def preview_remove_service(
        self,
        server_id: str,
        row: ServiceRow,
        target: ApplyTarget,
    ) -> ChangePreview:
        if not isinstance(row, ServiceRow):
            raise TypeError("row must be a ServiceRow")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        view, snapshot = self._actionable_snapshot(server_id, "remove a service")
        self._require_target_zones(snapshot, row.zone, target)
        validate_inventory_value("service", row.name, snapshot.available_services)
        runtime = snapshot.has_service(row.zone, row.name, False)
        permanent = snapshot.has_service(row.zone, row.name, True)
        if row.runtime != runtime or row.permanent != permanent:
            raise ValueError("The selected service row changed in the current snapshot.")
        for target_permanent in self._target_permanence(target):
            if not (permanent if target_permanent else runtime):
                raise ValueError("The service is absent from a requested remove target.")
        risk = assess_lockout_risk(
            RemoveServiceChange(row.zone, row.name),
            snapshot,
            ssh_port=view.port,
        )
        return ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Remove Firewall Service",
            zone=row.zone,
            resource=row.name,
            target=target,
            risk=risk,
            server_id=view.server_id,
            generation=view.generation,
        )

    def preview_change_interface_zone(
        self, server_id: str, request: ChangeInterfaceRequest
    ) -> ChangePreview:
        if not isinstance(request, ChangeInterfaceRequest):
            raise TypeError("request must be a ChangeInterfaceRequest")
        view, snapshot = self._actionable_snapshot(
            server_id, "change an interface zone"
        )
        runtime = self._interface_assignments(snapshot, permanent=False)
        permanent = self._interface_assignments(snapshot, permanent=True)
        if request.interface not in runtime and request.interface not in permanent:
            raise InvalidFirewallArgumentError(
                "interface", "is absent from the current firewall snapshot"
            )
        assignments = tuple(
            permanent.get(request.interface)
            if target_permanent
            else runtime.get(request.interface)
            for target_permanent in self._target_permanence(request.target)
        )
        if request.target is ApplyTarget.BOTH and assignments[0] != assignments[1]:
            raise InvalidFirewallArgumentError(
                "target",
                "runtime and permanent assignments differ; choose one target",
            )
        if any(current != request.current_zone for current in assignments):
            raise InvalidFirewallArgumentError(
                "current_zone", "does not match the current snapshot assignment"
            )
        for target_permanent in self._target_permanence(request.target):
            if snapshot.zone(request.new_zone, target_permanent) is None:
                raise InvalidFirewallArgumentError(
                    "new_zone", "is absent from a requested target inventory"
                )
        return ChangePreview(
            server_name=view.name,
            host=view.host,
            operation="Change Interface Zone",
            zone=f"{request.current_zone or 'Unassigned'} → {request.new_zone}",
            resource=request.interface,
            target=request.target,
            risk=(
                _active_interface_risk(view.port)
                if request.interface in runtime
                else _INACTIVE_INTERFACE_RISK
            ),
            server_id=view.server_id,
            generation=view.generation,
        )

    def apply_add_port(
        self,
        server_id: str,
        preview: ChangePreview,
        request: AddPortRequest,
    ) -> FirewallJobHandle:
        if not isinstance(preview, ChangePreview):
            raise TypeError("preview must be a ChangePreview")
        if not isinstance(request, AddPortRequest):
            raise TypeError("request must be an AddPortRequest")
        self._require_selected(server_id)
        try:
            current = self.preview_add_port(server_id, request)
        except (KeyError, RuntimeError, ValueError):
            raise RuntimeError(
                "The server or firewall inventory changed after confirmation."
            ) from None
        self._require_exact_preview(server_id, preview, current)
        return self._schedule(
            server_id,
            current.generation,
            "add_port",
            request.zone,
            request.port,
            request.protocol,
            request.target,
        )

    def apply_remove_port(
        self,
        server_id: str,
        preview: ChangePreview,
        row: PortRow,
        target: ApplyTarget,
    ) -> FirewallJobHandle:
        if not isinstance(preview, ChangePreview):
            raise TypeError("preview must be a ChangePreview")
        if not isinstance(row, PortRow):
            raise TypeError("row must be a PortRow")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        self._require_selected(server_id)
        try:
            current = self.preview_remove_port(server_id, row, target)
        except (KeyError, RuntimeError, ValueError):
            raise RuntimeError(
                "The server, selection, or firewall inventory changed after confirmation."
            ) from None
        self._require_exact_preview(server_id, preview, current)
        return self._schedule(
            server_id,
            current.generation,
            "remove_port",
            row.zone,
            row.port,
            row.protocol,
            target,
        )

    def apply_set_default_zone(
        self,
        server_id: str,
        preview: ChangePreview,
        new_zone: str,
        target: ApplyTarget,
    ) -> FirewallJobHandle:
        if not isinstance(preview, ChangePreview):
            raise TypeError("preview must be a ChangePreview")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        if target is not ApplyTarget.BOTH:
            raise InvalidFirewallArgumentError(
                "target", "default-zone changes require runtime and permanent"
            )
        self._require_selected(server_id)
        try:
            current = self.preview_set_default_zone(server_id, new_zone)
        except (KeyError, RuntimeError, ValueError):
            raise RuntimeError(
                "The server or firewall inventory changed after confirmation."
            ) from None
        self._require_exact_preview(server_id, preview, current)
        generation = current.generation
        if generation is None:
            raise RuntimeError("The confirmed preview has no session generation.")
        internal = self.server_controller._schedule_default_zone_change(
            server_id,
            generation,
            new_zone,
            target,
        )
        return self._bind_internal(
            server_id, generation, "set_default_zone", internal
        )

    def apply_add_service(
        self,
        server_id: str,
        preview: ChangePreview,
        request: AddServiceRequest,
    ) -> FirewallJobHandle:
        if not isinstance(preview, ChangePreview):
            raise TypeError("preview must be a ChangePreview")
        if not isinstance(request, AddServiceRequest):
            raise TypeError("request must be an AddServiceRequest")
        self._require_selected(server_id)
        try:
            current = self.preview_add_service(server_id, request)
        except (KeyError, RuntimeError, ValueError):
            raise RuntimeError(
                "The server or firewall inventory changed after confirmation."
            ) from None
        self._require_exact_preview(server_id, preview, current)
        view = self.server_controller.session_view(server_id)
        if view.snapshot is None:
            raise RuntimeError("The firewall inventory changed after confirmation.")
        effective_target = self._missing_service_target(view.snapshot, request)
        return self._schedule_service(
            server_id,
            current.generation,
            "add_service",
            request.zone,
            request.service,
            effective_target,
        )

    def apply_remove_service(
        self,
        server_id: str,
        preview: ChangePreview,
        row: ServiceRow,
        target: ApplyTarget,
    ) -> FirewallJobHandle:
        if not isinstance(preview, ChangePreview):
            raise TypeError("preview must be a ChangePreview")
        if not isinstance(row, ServiceRow):
            raise TypeError("row must be a ServiceRow")
        if not isinstance(target, ApplyTarget):
            raise TypeError("target must be an ApplyTarget")
        self._require_selected(server_id)
        try:
            current = self.preview_remove_service(server_id, row, target)
        except (KeyError, RuntimeError, ValueError):
            raise RuntimeError(
                "The server, selection, or firewall inventory changed after confirmation."
            ) from None
        self._require_exact_preview(server_id, preview, current)
        return self._schedule_service(
            server_id,
            current.generation,
            "remove_service",
            row.zone,
            row.name,
            target,
        )

    def apply_change_interface_zone(
        self,
        server_id: str,
        preview: ChangePreview,
        request: ChangeInterfaceRequest,
    ) -> FirewallJobHandle:
        if not isinstance(preview, ChangePreview):
            raise TypeError("preview must be a ChangePreview")
        if not isinstance(request, ChangeInterfaceRequest):
            raise TypeError("request must be a ChangeInterfaceRequest")
        self._require_selected(server_id)
        try:
            current = self.preview_change_interface_zone(server_id, request)
        except (KeyError, RuntimeError, ValueError):
            raise RuntimeError(
                "The selected interface or firewall inventory changed after "
                "confirmation."
            ) from None
        self._require_exact_preview(server_id, preview, current)
        generation = current.generation
        if generation is None:
            raise RuntimeError("The confirmed preview has no session generation.")
        internal = self.server_controller._schedule_interface_change(
            server_id,
            generation,
            request.interface,
            request.new_zone,
            request.target,
        )
        return self._bind_internal(
            server_id, generation, "change_interface_zone", internal
        )

    def _schedule(
        self,
        server_id: str,
        generation: int | None,
        operation: str,
        zone: str,
        port: str,
        protocol: str,
        target: ApplyTarget,
    ) -> FirewallJobHandle:
        if generation is None:
            raise RuntimeError("The confirmed preview has no session generation.")
        key = (server_id, generation, operation)
        if key in self._pending:
            raise RuntimeError("A matching firewall operation is already pending.")
        internal = self.server_controller._schedule_port_change(
            server_id,
            generation,
            operation,
            zone,
            port,
            protocol,
            target,
        )
        return self._bind_internal(server_id, generation, operation, internal)

    def _schedule_service(
        self,
        server_id: str,
        generation: int | None,
        operation: str,
        zone: str,
        service: str,
        target: ApplyTarget,
    ) -> FirewallJobHandle:
        if generation is None:
            raise RuntimeError("The confirmed preview has no session generation.")
        key = (server_id, generation, operation)
        if key in self._pending:
            raise RuntimeError("A matching firewall operation is already pending.")
        internal = self.server_controller._schedule_service_change(
            server_id,
            generation,
            operation,
            zone,
            service,
            target,
        )
        return self._bind_internal(server_id, generation, operation, internal)

    @staticmethod
    def _interface_assignments(
        snapshot: FirewallSnapshot, *, permanent: bool
    ) -> dict[str, str]:
        assignments: dict[str, str] = {}
        zones = snapshot.permanent_zones if permanent else snapshot.runtime_zones
        for zone in zones:
            for interface in zone.interfaces:
                existing = assignments.get(interface)
                if existing is not None and existing != zone.name:
                    raise InvalidFirewallArgumentError(
                        "interface",
                        "has multiple zone assignments in one snapshot target",
                    )
                assignments[interface] = zone.name
        return assignments

    def _bind_internal(
        self,
        server_id: str,
        generation: int,
        operation: str,
        internal: ControllerJobHandle,
    ) -> FirewallJobHandle:
        key = (server_id, generation, operation)
        if key in self._pending:
            raise RuntimeError("A matching firewall operation is already pending.")
        facade = FirewallJobHandle(server_id, generation, operation)
        pending = _PendingFirewallIntent(
            server_id, generation, operation, facade, internal
        )
        self._pending[key] = pending
        internal.started.connect(partial(self._internal_started, internal))
        internal.succeeded.connect(partial(self._internal_succeeded, internal))
        internal.failed.connect(partial(self._internal_failed, internal))
        internal.finished.connect(partial(self._internal_finished, internal))
        return facade

    def _internal_started(
        self,
        internal: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> None:
        pending = self._matching(internal, server_id, generation, operation)
        if pending is not None:
            pending.facade.started.emit(server_id, generation, operation)

    def _internal_succeeded(
        self,
        internal: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
        value: object,
    ) -> None:
        pending = self._matching(internal, server_id, generation, operation)
        if (
            pending is None
            or not isinstance(value, CompositeOperationResult)
            or value.operation != operation
        ):
            return
        try:
            view = self.server_controller.session_view(server_id)
        except KeyError:
            return
        if view.generation != generation or view.snapshot is None:
            return
        safe_result = self._safe_result(value)
        self.snapshot_changed.emit(server_id, view.snapshot)
        self.operation_result.emit(server_id, safe_result)
        pending.facade.succeeded.emit(
            server_id, generation, operation, safe_result
        )
        pending.outcome_emitted = True

    def _internal_failed(
        self,
        internal: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
        error: object,
    ) -> None:
        pending = self._matching(internal, server_id, generation, operation)
        if pending is None:
            return
        public_error = (
            error
            if isinstance(error, ControllerOperationError)
            else ControllerOperationError(
                server_id, operation, "operation", "The remote operation failed."
            )
        )
        if not pending.error_emitted:
            self.error_raised.emit(server_id, public_error)
            pending.error_emitted = True
        pending.facade.failed.emit(server_id, generation, operation, public_error)
        pending.outcome_emitted = True

    def _internal_finished(
        self,
        internal: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> None:
        pending = self._matching(internal, server_id, generation, operation)
        if pending is None:
            return
        key = (server_id, generation, operation)
        self._pending.pop(key, None)
        pending.facade.finished.emit(server_id, generation, operation)

    def _forward_matching_error(self, server_id: str, error: object) -> None:
        if not isinstance(error, ControllerOperationError):
            return
        candidates = tuple(
            pending
            for pending in self._pending.values()
            if pending.server_id == server_id
            and pending.operation == error.operation
            and not pending.error_emitted
        )
        if len(candidates) != 1:
            return
        candidates[0].error_emitted = True
        self.error_raised.emit(server_id, error)

    def _matching(
        self,
        internal: ControllerJobHandle,
        server_id: str,
        generation: int,
        operation: str,
    ) -> _PendingFirewallIntent | None:
        pending = self._pending.get((server_id, generation, operation))
        if pending is None or pending.internal is not internal:
            return None
        try:
            view = self.server_controller.session_view(server_id)
        except KeyError:
            return None
        if view.generation != generation:
            return None
        return pending

    def _actionable_snapshot(
        self, server_id: str, action: str
    ) -> tuple[ServerSessionView, FirewallSnapshot]:
        view = self.server_controller.session_view(server_id)
        if view.status is not ConnectionStatus.CONNECTED:
            raise RuntimeError(f"Cannot {action} while the server is disconnected.")
        if view.busy_operation is not None:
            raise RuntimeError(f"Cannot {action} while the server is busy.")
        if view.snapshot is None:
            raise RuntimeError("No firewall snapshot is available.")
        if view.snapshot.stale:
            raise RuntimeError("The firewall snapshot is stale.")
        return view, view.snapshot

    def _require_selected(self, server_id: str) -> None:
        if self.server_controller.selected_server_id != server_id:
            raise RuntimeError("The confirmed server is no longer selected.")

    @staticmethod
    def _target_permanence(target: ApplyTarget) -> tuple[bool, ...]:
        if target is ApplyTarget.RUNTIME:
            return (False,)
        if target is ApplyTarget.PERMANENT:
            return (True,)
        if target is ApplyTarget.BOTH:
            return (True, False)
        raise TypeError("target must be an ApplyTarget")

    @classmethod
    def _require_target_zones(
        cls, snapshot: FirewallSnapshot, zone: str, target: ApplyTarget
    ) -> None:
        for permanent in cls._target_permanence(target):
            if snapshot.zone(zone, permanent) is None:
                raise ValueError("The zone is absent from a requested target inventory.")

    @classmethod
    def _missing_service_target(
        cls, snapshot: FirewallSnapshot, request: AddServiceRequest
    ) -> ApplyTarget:
        missing = tuple(
            permanent
            for permanent in cls._target_permanence(request.target)
            if not snapshot.has_service(request.zone, request.service, permanent)
        )
        if missing == (True, False):
            return ApplyTarget.BOTH
        if missing == (True,):
            return ApplyTarget.PERMANENT
        if missing == (False,):
            return ApplyTarget.RUNTIME
        raise RuntimeError("The service is already present in every requested target.")

    @staticmethod
    def _require_exact_preview(
        server_id: str, supplied: ChangePreview, current: ChangePreview
    ) -> None:
        if (
            supplied != current
            or supplied.server_id != server_id
            or supplied.generation != current.generation
        ):
            raise RuntimeError("The confirmed preview no longer matches the request.")

    @classmethod
    def _safe_result(
        cls, result: CompositeOperationResult
    ) -> CompositeOperationResult:
        return CompositeOperationResult(
            operation=result.operation,
            runtime=cls._safe_target(result.runtime),
            permanent=cls._safe_target(result.permanent),
        )

    @staticmethod
    def _safe_target(result: TargetResult | None) -> TargetResult | None:
        if result is None:
            return None
        if result.is_success:
            message = ""
        elif result.authentication_failed:
            message = "Authentication failed after an earlier firewall mutation."
        elif result.execution_status is TargetStatus.NOT_RUN:
            message = "This target was not run."
        elif result.execution_status is TargetStatus.FAILED:
            message = "The firewalld target change failed."
        elif result.verification_status is TargetStatus.FAILED:
            message = "The requested target state could not be verified."
        else:
            message = "The target result is incomplete."
        return TargetResult(
            target=result.target,
            execution_status=result.execution_status,
            verification_status=result.verification_status,
            result=None,
            message=message,
            authentication_failed=result.authentication_failed,
        )


__all__ = ["FirewallController", "FirewallJobHandle"]
