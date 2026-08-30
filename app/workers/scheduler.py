"""Keyed Qt thread-pool scheduling for remote server operations."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Generic, TypeVar, cast

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, Signal, Slot


T = TypeVar("T")


class JobHandle(QObject, Generic[T]):
    """Qt-thread-owned signal handle for one scheduled operation."""

    started = Signal(str, int, str)
    succeeded = Signal(str, int, str, object)
    failed = Signal(str, int, str, object)
    finished = Signal(str, int, str)

    _start_requested = Signal()
    _success_requested = Signal(object)
    _failure_requested = Signal(object)
    _finish_requested = Signal()
    _delivery_complete = Signal(object)

    def __init__(self, server_id: str, generation: int, operation: str) -> None:
        super().__init__()
        self.server_id = server_id
        self.generation = generation
        self.operation = operation
        queued = Qt.ConnectionType.QueuedConnection
        self._start_requested.connect(self._publish_started, queued)
        self._success_requested.connect(self._publish_succeeded, queued)
        self._failure_requested.connect(self._publish_failed, queued)
        self._finish_requested.connect(self._publish_finished, queued)

    @Slot()
    def _publish_started(self) -> None:
        self.started.emit(self.server_id, self.generation, self.operation)

    @Slot(object)
    def _publish_succeeded(self, value: object) -> None:
        self.succeeded.emit(
            self.server_id, self.generation, self.operation, value
        )

    @Slot(object)
    def _publish_failed(self, error: object) -> None:
        self.failed.emit(self.server_id, self.generation, self.operation, error)

    @Slot()
    def _publish_finished(self) -> None:
        self.finished.emit(self.server_id, self.generation, self.operation)
        self._delivery_complete.emit(self)


@dataclass
class _QueuedJob(Generic[T]):
    handle: JobHandle[T]
    work: Callable[[], T]
    runnable: _OperationRunnable[T] | None = None
    started: bool = False


class _OperationRunnable(QRunnable, Generic[T]):
    def __init__(
        self, scheduler: OperationScheduler, job: _QueuedJob[T]
    ) -> None:
        super().__init__()
        self._scheduler = scheduler
        self._job = job

    @Slot()
    def run(self) -> None:
        if not self._scheduler._mark_started(self._job):
            return
        self._job.handle._start_requested.emit()
        try:
            value = self._job.work()
        except Exception as error:
            self._job.handle._failure_requested.emit(error)
        else:
            self._job.handle._success_requested.emit(value)
        finally:
            self._job.handle._finish_requested.emit()
            self._scheduler._complete(self._job)


class OperationScheduler(QObject):
    """Run one FIFO operation at a time per server on a shared pool."""

    def __init__(self, max_threads: int = 4) -> None:
        if isinstance(max_threads, bool) or not isinstance(max_threads, int):
            raise TypeError("max_threads must be an integer")
        if max_threads < 1:
            raise ValueError("max_threads must be at least 1")
        super().__init__()
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(max_threads)
        self._lock = Lock()
        self._queues: dict[str, deque[_QueuedJob[object]]] = {}
        self._delivery_holds: set[JobHandle[object]] = set()

    def submit(
        self,
        server_id: str,
        generation: int,
        operation: str,
        work: Callable[[], T],
    ) -> JobHandle[T]:
        """Enqueue work, preserving its routing metadata exactly."""
        self._validate_submission(server_id, generation, operation, work)
        handle: JobHandle[T] = JobHandle(server_id, generation, operation)
        handle._delivery_complete.connect(self._release_handle)
        job = _QueuedJob(handle=handle, work=work)
        erased_job = cast(_QueuedJob[object], job)
        erased_handle = cast(JobHandle[object], handle)

        with self._lock:
            queue = self._queues.setdefault(server_id, deque())
            queue.append(erased_job)
            self._delivery_holds.add(erased_handle)
            if len(queue) == 1:
                self._schedule_locked(erased_job)
        return handle

    def cancel_pending(self, server_id: str) -> None:
        """Finish queued work without interrupting a job already executing."""
        if not isinstance(server_id, str):
            raise TypeError("server_id must be a string")
        cancelled: list[_QueuedJob[object]] = []
        with self._lock:
            queue = self._queues.get(server_id)
            if not queue:
                return

            head = queue[0]
            if not head.started and head.runnable is not None:
                if self._pool.tryTake(head.runnable):
                    cancelled.extend(queue)
                    queue.clear()

            if queue:
                running_head = queue.popleft()
                cancelled.extend(queue)
                queue.clear()
                queue.append(running_head)
            if not queue:
                del self._queues[server_id]

        for job in cancelled:
            job.handle._finish_requested.emit()

    def is_busy(self, server_id: str) -> bool:
        """Return whether the server has executing or queued work."""
        if not isinstance(server_id, str):
            raise TypeError("server_id must be a string")
        with self._lock:
            return bool(self._queues.get(server_id))

    def wait_for_done(self, timeout_ms: int = -1) -> bool:
        """Wait for pool work to drain, primarily for orderly shutdown/tests."""
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int):
            raise TypeError("timeout_ms must be an integer")
        if timeout_ms < -1:
            raise ValueError("timeout_ms must be -1 or non-negative")
        return self._pool.waitForDone(timeout_ms)

    @staticmethod
    def _validate_submission(
        server_id: object,
        generation: object,
        operation: object,
        work: object,
    ) -> None:
        for name, value in (("server_id", server_id), ("operation", operation)):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value.strip():
                raise ValueError(f"{name} must not be empty")
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise TypeError("generation must be an integer")
        if not callable(work):
            raise TypeError("work must be callable")

    def _schedule_locked(self, job: _QueuedJob[object]) -> None:
        runnable = _OperationRunnable(self, job)
        job.runnable = runnable
        self._pool.start(runnable)

    def _mark_started(self, job: _QueuedJob[object]) -> bool:
        with self._lock:
            queue = self._queues.get(job.handle.server_id)
            if not queue or queue[0] is not job:
                return False
            job.started = True
            return True

    def _complete(self, job: _QueuedJob[object]) -> None:
        with self._lock:
            queue = self._queues.get(job.handle.server_id)
            if not queue or queue[0] is not job:
                return
            queue.popleft()
            if queue:
                self._schedule_locked(queue[0])
            else:
                del self._queues[job.handle.server_id]

    @Slot(object)
    def _release_handle(self, handle: object) -> None:
        with self._lock:
            self._delivery_holds.discard(cast(JobHandle[object], handle))
