"""Credential-safe logging utilities for the desktop application."""

from __future__ import annotations

import copy
import logging
import re
import traceback
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import is_dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock
from types import TracebackType

from PySide6.QtCore import QObject, Signal


_LOG_FILE_NAME = "remote-firewalld-manager.log"
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_SENSITIVE_VALUE_PATTERN = re.compile(
    r"""(?ix)
    (?P<key>[\"']?(?:password|passphrase|credential)[\"']?)
    (?P<separator>\s*[:=]\s*)
    (?P<value>
        \"(?:\\.|[^\"])*\"
        | '(?:\\.|[^'])*'
        | [^,;}\]\n]+?
    )
    (?=
        \s*(?:[,;}\]]|$)
        | \s+(?:(?:[\"']?(?:password|passphrase|credential)[\"']?)\s*[:=]|\w+\s*=)
    )
    """
)


class SecretRedactionFilter(logging.Filter):
    """Remove configured secrets and common credential fields from log records."""

    def __init__(self, secrets: Iterable[str]):
        super().__init__()
        self._credential_safe_redactor = True
        self._secrets = tuple(
            sorted(
                {secret for secret in secrets if isinstance(secret, str) and secret.strip()},
                key=len,
                reverse=True,
            )
        )

    def filter(self, record: logging.LogRecord) -> bool:
        sanitized = copy.copy(record)
        sanitized.msg = self._sanitize_value(record.msg)
        sanitized.args = self._sanitize_value(record.args)

        try:
            message = sanitized.getMessage()
        except (TypeError, ValueError):
            message = sanitized.msg if isinstance(sanitized.msg, str) else "[UNFORMATTABLE MESSAGE]"

        record.msg = self._redact_text(message)
        record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = self._render_exception(record.exc_info)
        elif record.exc_text:
            record.exc_text = self._redact_text(record.exc_text)
        return True

    def _sanitize_value(
        self,
        value: object,
        active_ids: set[int] | None = None,
    ) -> object:
        if active_ids is None:
            active_ids = set()
        if self._is_app_config(value):
            return "[REDACTED CONFIG]"
        if isinstance(value, (Mapping, tuple, list, set, frozenset)):
            value_id = id(value)
            if value_id in active_ids:
                return "[REDACTED CYCLE]"
            active_ids.add(value_id)
            try:
                if isinstance(value, Mapping):
                    return {
                        key: "[REDACTED]"
                        if self._is_sensitive_key(key)
                        else self._sanitize_value(item, active_ids)
                        for key, item in value.items()
                    }
                if isinstance(value, tuple):
                    return tuple(self._sanitize_value(item, active_ids) for item in value)
                if isinstance(value, list):
                    return [self._sanitize_value(item, active_ids) for item in value]
                if isinstance(value, set):
                    return {self._sanitize_value(item, active_ids) for item in value}
                return frozenset(self._sanitize_value(item, active_ids) for item in value)
            finally:
                active_ids.remove(value_id)
        return self._redact_text(value) if isinstance(value, str) else value

    @staticmethod
    def _is_app_config(value: object) -> bool:
        value_type = type(value)
        return is_dataclass(value) and value_type.__module__.startswith("app.config")

    @staticmethod
    def _is_sensitive_key(key: object) -> bool:
        return isinstance(key, str) and key.strip(" '\"").casefold() in {
            "password",
            "passphrase",
            "credential",
        }

    def _render_exception(
        self,
        exc_info: tuple[
            type[BaseException] | None,
            BaseException | None,
            TracebackType | None,
        ],
    ) -> str:
        exception = exc_info[1]
        exception_args = getattr(exception, "args", ()) if exception else ()
        sanitized_args = self._sanitize_value(exception_args)
        if exception and self._contains_app_config(exception_args):
            return f"{type(exception).__name__}: [REDACTED CONFIG]"
        if "[REDACTED CYCLE]" in repr(sanitized_args):
            return self._redact_text(f"{type(exception).__name__}: {sanitized_args}")
        return self._redact_text("".join(traceback.format_exception(*exc_info)))

    def _contains_app_config(
        self,
        value: object,
        active_ids: set[int] | None = None,
    ) -> bool:
        if active_ids is None:
            active_ids = set()
        if self._is_app_config(value):
            return True
        if isinstance(value, Mapping):
            value_id = id(value)
            if value_id in active_ids:
                return False
            active_ids.add(value_id)
            try:
                return any(self._contains_app_config(item, active_ids) for item in value.values())
            finally:
                active_ids.remove(value_id)
        if isinstance(value, (tuple, list, set, frozenset)):
            value_id = id(value)
            if value_id in active_ids:
                return False
            active_ids.add(value_id)
            try:
                return any(self._contains_app_config(item, active_ids) for item in value)
            finally:
                active_ids.remove(value_id)
        return False

    def _redact_text(self, text: str) -> str:
        redacted = text
        for secret in self._secrets:
            redacted = redacted.replace(secret, "[REDACTED]")
        return _SENSITIVE_VALUE_PATTERN.sub(r"\g<key>\g<separator>[REDACTED]", redacted)


def _replace_redactor(
    filterer: logging.Filterer,
    redactor: SecretRedactionFilter,
) -> None:
    for existing_filter in filterer.filters[:]:
        if isinstance(existing_filter, SecretRedactionFilter):
            filterer.removeFilter(existing_filter)
    filterer.addFilter(redactor)


def configure_logging(log_dir: Path, secrets: Iterable[str]) -> logging.Logger:
    """Configure the application logger with one credential-safe rotating file."""
    target_directory = Path(log_dir)
    target_directory.mkdir(parents=True, exist_ok=True)
    log_path = target_directory / _LOG_FILE_NAME

    logger = logging.getLogger("remote_firewalld_manager")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    redaction_filter = SecretRedactionFilter(secrets)
    _replace_redactor(logger, redaction_filter)

    existing_handler = next(
        (
            handler
            for handler in logger.handlers
            if getattr(handler, "_remote_firewalld_logging_handler", False)
        ),
        None,
    )
    if existing_handler and Path(existing_handler.baseFilename) != log_path.resolve():
        logger.removeHandler(existing_handler)
        existing_handler.close()
        existing_handler = None

    if not existing_handler:
        handler = RotatingFileHandler(
            log_path,
            maxBytes=2 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"))
        handler._remote_firewalld_logging_handler = True
        logger.addHandler(handler)

    for handler in logger.handlers:
        _replace_redactor(handler, redaction_filter)
    return logger


class ServerLogBuffer(QObject):
    """Maintain a bounded, thread-safe in-memory view of per-server log entries."""

    entries_changed = Signal(str)

    def __init__(self, max_entries: int = 500, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._entries: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=max_entries))
        self._lock = RLock()
        self._formatter = logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
        self._secrets = {
            secret
            for secret in secrets
            if isinstance(secret, str) and secret.strip()
        }
        self._redaction_filter = SecretRedactionFilter(self._secrets)

    def add_secrets(self, secrets: Iterable[str]) -> None:
        """Add defense-in-depth redaction values without exposing existing ones."""
        additions = {
            secret
            for secret in secrets
            if isinstance(secret, str) and secret.strip()
        }
        if not additions:
            return
        with self._lock:
            self._secrets.update(additions)
            self._redaction_filter = SecretRedactionFilter(self._secrets)

    def append(self, record: logging.LogRecord) -> None:
        server_id = record.server_id if isinstance(getattr(record, "server_id", None), str) else "default"
        sanitized = copy.copy(record)
        with self._lock:
            self._redaction_filter.filter(sanitized)
            entry = self._formatter.format(sanitized)
            self._entries[server_id].append(entry)
        self.entries_changed.emit(server_id)

    def append_message(
        self,
        server_id: str,
        message: str,
        *,
        level: int = logging.INFO,
    ) -> None:
        """Sanitize and append one already-structured application message."""
        if not isinstance(server_id, str) or not server_id:
            raise TypeError("server_id must be a nonempty string")
        if not isinstance(message, str):
            raise TypeError("message must be a string")
        if isinstance(level, bool) or not isinstance(level, int):
            raise TypeError("level must be an integer logging level")
        record = logging.LogRecord(
            "remote_firewalld_manager",
            level,
            "",
            0,
            message,
            (),
            None,
        )
        record.server_id = server_id
        self.append(record)

    def entries(self, server_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries.get(server_id, ()))

    def clear(self, server_id: str) -> None:
        with self._lock:
            if server_id in self._entries:
                self._entries[server_id].clear()
        self.entries_changed.emit(server_id)
