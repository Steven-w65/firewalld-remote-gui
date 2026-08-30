from __future__ import annotations

from collections.abc import Callable
from threading import Event, Lock
from typing import Any

import pytest
from PySide6.QtCore import QObject, QThread, Slot

from app.workers.scheduler import JobHandle, OperationScheduler


def _wait_idle(qtbot: Any, scheduler: OperationScheduler, *server_ids: str) -> None:
    qtbot.waitUntil(
        lambda: all(not scheduler.is_busy(server_id) for server_id in server_ids),
        timeout=3000,
    )
    assert scheduler.wait_for_done(3000)


def test_jobs_for_same_server_run_in_strict_fifo_without_overlap(qtbot: Any) -> None:
    scheduler = OperationScheduler(max_threads=4)
    first_started = Event()
    release_first = Event()
    second_started = Event()
    order: list[str] = []
    lock = Lock()
    active = 0
    maximum_active = 0

    def record(name: str, release: Event | None = None) -> None:
        nonlocal active, maximum_active
        with lock:
            active += 1
            maximum_active = max(maximum_active, active)
            order.append(name)
        if name == "first":
            first_started.set()
        else:
            second_started.set()
        if release is not None:
            assert release.wait(2)
        with lock:
            active -= 1

    first = scheduler.submit(
        "web01", 1, "first", lambda: record("first", release_first)
    )
    second = scheduler.submit("web01", 1, "second", lambda: record("second"))

    assert first_started.wait(1)
    assert not second_started.wait(0.1)
    assert scheduler.is_busy("web01")
    release_first.set()
    assert second_started.wait(1)
    _wait_idle(qtbot, scheduler, "web01")

    assert order == ["first", "second"]
    assert maximum_active == 1
    assert first is not second


def test_jobs_for_different_servers_can_overlap(qtbot: Any) -> None:
    scheduler = OperationScheduler(max_threads=4)
    reached = {"a": Event(), "b": Event()}
    release = Event()

    def block(server_id: str) -> str:
        reached[server_id].set()
        assert release.wait(2)
        return server_id

    scheduler.submit("a", 1, "read", lambda: block("a"))
    scheduler.submit("b", 2, "read", lambda: block("b"))

    assert reached["a"].wait(1)
    assert reached["b"].wait(1)
    assert scheduler.is_busy("a")
    assert scheduler.is_busy("b")
    release.set()
    _wait_idle(qtbot, scheduler, "a", "b")


class _SignalReceiver(QObject):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[tuple[Any, ...]] = []
        self.threads: list[QThread] = []

    def _record(self, *event: Any) -> None:
        self.events.append(event)
        self.threads.append(QThread.currentThread())

    @Slot(str, int, str)
    def started(self, server_id: str, generation: int, operation: str) -> None:
        self._record("started", server_id, generation, operation)

    @Slot(str, int, str, object)
    def succeeded(
        self, server_id: str, generation: int, operation: str, value: object
    ) -> None:
        self._record("succeeded", server_id, generation, operation, value)

    @Slot(str, int, str, object)
    def failed(
        self, server_id: str, generation: int, operation: str, error: object
    ) -> None:
        self._record("failed", server_id, generation, operation, error)

    @Slot(str, int, str)
    def finished(self, server_id: str, generation: int, operation: str) -> None:
        self._record("finished", server_id, generation, operation)


def _connect(handle: JobHandle, receiver: _SignalReceiver) -> None:
    handle.started.connect(receiver.started)
    handle.succeeded.connect(receiver.succeeded)
    handle.failed.connect(receiver.failed)
    handle.finished.connect(receiver.finished)


def test_success_signals_have_exact_order_payload_and_receiver_thread(
    qtbot: Any,
) -> None:
    scheduler = OperationScheduler(max_threads=2)
    release = Event()
    entered = Event()
    receiver = _SignalReceiver()

    def work() -> dict[str, bool]:
        entered.set()
        assert release.wait(2)
        return {"ok": True}

    handle = scheduler.submit(" web01 ", -3, " refresh ", work)
    _connect(handle, receiver)
    assert entered.wait(1)
    release.set()
    qtbot.waitUntil(lambda: len(receiver.events) == 3, timeout=3000)
    _wait_idle(qtbot, scheduler, " web01 ")

    assert receiver.events == [
        ("started", " web01 ", -3, " refresh "),
        ("succeeded", " web01 ", -3, " refresh ", {"ok": True}),
        ("finished", " web01 ", -3, " refresh "),
    ]
    assert receiver.threads == [receiver.thread()] * 3
    assert receiver.thread() is handle.thread()


def test_exception_signals_failure_once_then_advances_same_server(
    qtbot: Any,
) -> None:
    scheduler = OperationScheduler(max_threads=2)
    release = Event()
    entered = Event()
    next_ran = Event()
    receiver = _SignalReceiver()
    expected = RuntimeError("remote read failed")

    def fail() -> None:
        entered.set()
        assert release.wait(2)
        raise expected

    first = scheduler.submit("web01", 9, "read", fail)
    _connect(first, receiver)
    scheduler.submit("web01", 9, "next", next_ran.set)
    assert entered.wait(1)
    release.set()
    assert next_ran.wait(1)
    qtbot.waitUntil(lambda: len(receiver.events) == 3, timeout=3000)
    _wait_idle(qtbot, scheduler, "web01")

    assert receiver.events[:2] == [
        ("started", "web01", 9, "read"),
        ("failed", "web01", 9, "read", expected),
    ]
    assert receiver.events[2] == ("finished", "web01", 9, "read")


def test_cancel_pending_does_not_interrupt_running_head(qtbot: Any) -> None:
    scheduler = OperationScheduler(max_threads=2)
    running = Event()
    release = Event()
    pending_ran = Event()
    running_receiver = _SignalReceiver()
    pending_receiver = _SignalReceiver()

    def first() -> str:
        running.set()
        assert release.wait(2)
        return "complete"

    first_handle = scheduler.submit("web01", 1, "running", first)
    pending_handle = scheduler.submit("web01", 1, "pending", pending_ran.set)
    _connect(first_handle, running_receiver)
    _connect(pending_handle, pending_receiver)
    assert running.wait(1)

    scheduler.cancel_pending("web01")
    qtbot.waitUntil(lambda: len(pending_receiver.events) == 1, timeout=1000)
    assert pending_receiver.events == [("finished", "web01", 1, "pending")]
    assert not pending_ran.is_set()
    assert scheduler.is_busy("web01")

    release.set()
    qtbot.waitUntil(lambda: len(running_receiver.events) == 3, timeout=3000)
    _wait_idle(qtbot, scheduler, "web01")
    assert [event[0] for event in running_receiver.events] == [
        "started",
        "succeeded",
        "finished",
    ]


def test_cancel_pending_can_remove_pool_queued_server_head(qtbot: Any) -> None:
    scheduler = OperationScheduler(max_threads=1)
    blocker_entered = Event()
    release = Event()
    queued_ran = Event()
    receiver = _SignalReceiver()

    def block() -> None:
        blocker_entered.set()
        assert release.wait(2)

    scheduler.submit("a", 1, "block", block)
    assert blocker_entered.wait(1)
    queued = scheduler.submit("b", 4, "queued", queued_ran.set)
    _connect(queued, receiver)

    scheduler.cancel_pending("b")
    qtbot.waitUntil(lambda: len(receiver.events) == 1, timeout=1000)
    assert receiver.events == [("finished", "b", 4, "queued")]
    assert not scheduler.is_busy("b")
    assert not queued_ran.is_set()

    release.set()
    _wait_idle(qtbot, scheduler, "a", "b")


def test_cancel_pending_removes_entire_pool_queued_server_fifo(qtbot: Any) -> None:
    scheduler = OperationScheduler(max_threads=1)
    blocker_entered = Event()
    release = Event()
    ran = [Event(), Event(), Event()]
    receivers = [_SignalReceiver(), _SignalReceiver(), _SignalReceiver()]

    def block() -> None:
        blocker_entered.set()
        assert release.wait(2)

    scheduler.submit("a", 1, "block", block)
    assert blocker_entered.wait(1)
    for index, (event, receiver) in enumerate(zip(ran, receivers, strict=True)):
        handle = scheduler.submit("b", index, f"queued-{index}", event.set)
        _connect(handle, receiver)

    scheduler.cancel_pending("b")
    qtbot.waitUntil(
        lambda: all(len(receiver.events) == 1 for receiver in receivers),
        timeout=1000,
    )
    assert [receiver.events for receiver in receivers] == [
        [("finished", "b", 0, "queued-0")],
        [("finished", "b", 1, "queued-1")],
        [("finished", "b", 2, "queued-2")],
    ]
    assert not any(event.is_set() for event in ran)
    assert not scheduler.is_busy("b")

    release.set()
    _wait_idle(qtbot, scheduler, "a", "b")


def test_cancel_pending_is_idempotent_for_unknown_and_idle_server(qtbot: Any) -> None:
    scheduler = OperationScheduler(max_threads=1)
    scheduler.cancel_pending("unknown")
    scheduler.cancel_pending("unknown")
    assert not scheduler.is_busy("unknown")
    assert scheduler.wait_for_done(100)


@pytest.mark.parametrize(
    ("factory", "error_type"),
    [
        (lambda: OperationScheduler(max_threads=0), ValueError),
        (lambda: OperationScheduler(max_threads=-1), ValueError),
        (lambda: OperationScheduler(max_threads=True), TypeError),
        (lambda: OperationScheduler(max_threads=1.5), TypeError),
    ],
)
def test_invalid_thread_count_is_rejected(
    qtbot: Any, factory: Callable[[], object], error_type: type[Exception]
) -> None:
    with pytest.raises(error_type):
        factory()


@pytest.mark.parametrize(
    ("server_id", "generation", "operation", "work", "error_type"),
    [
        ("", 1, "read", lambda: None, ValueError),
        ("   ", 1, "read", lambda: None, ValueError),
        (3, 1, "read", lambda: None, TypeError),
        ("web01", True, "read", lambda: None, TypeError),
        ("web01", 1.0, "read", lambda: None, TypeError),
        ("web01", 1, "", lambda: None, ValueError),
        ("web01", 1, "   ", lambda: None, ValueError),
        ("web01", 1, 7, lambda: None, TypeError),
        ("web01", 1, "read", None, TypeError),
    ],
)
def test_invalid_submission_is_rejected_without_marking_busy(
    qtbot: Any,
    server_id: Any,
    generation: Any,
    operation: Any,
    work: Any,
    error_type: type[Exception],
) -> None:
    scheduler = OperationScheduler(max_threads=1)
    with pytest.raises(error_type):
        scheduler.submit(server_id, generation, operation, work)
    if isinstance(server_id, str):
        assert not scheduler.is_busy(server_id)
    assert scheduler.wait_for_done(100)
