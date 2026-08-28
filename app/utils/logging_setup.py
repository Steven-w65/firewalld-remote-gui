"""Credential-safe logging utilities for the desktop application."""

from __future__ import annotations

import copy
import logging
import re
import traceback
from collections import defaultdict, deque
from collections.abc import Iterable
from logging.handlers import RotatingFileHandler
from pathlib import Path
from threading import RLock


_LOG_FILE_NAME = "remote-firewalld-manager.log"
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_SENSITIVE_VALUE_PATTERN = re.compile(
    r"(?i)\b(password|passphrase|credential)\b(\s*[=:]\s*)([^\s,;]+)"
)


class SecretRedactionFilter(logging.Filter):
    """Remove configured secrets and common credential fields from log records."""

    def __init__(self, secrets: Iterable[str]):
        super().__init__()
        self._secrets = tuple(
            sorted(
                {secret for secret in secrets if isinstance(secret, str) and secret.strip()},
                key=len,
                reverse=True,
            )
        )

    def filter(self, record: logging.LogRecord) -> bool:
        sanitized = copy.copy(record)
        sanitized.msg = self._redact_text(record.msg) if isinstance(record.msg, str) else record.msg
        sanitized.args = self._redact_arguments(record.args)

        try:
            message = sanitized.getMessage()
        except (TypeError, ValueError):
            message = sanitized.msg if isinstance(sanitized.msg, str) else "[UNFORMATTABLE MESSAGE]"

        record.msg = self._redact_text(message)
        record.args = ()
        if record.exc_info and not record.exc_text:
            record.exc_text = self._redact_text("".join(traceback.format_exception(*record.exc_info)))
        elif record.exc_text:
            record.exc_text = self._redact_text(record.exc_text)
        return True

    def _redact_arguments(self, arguments):
        if isinstance(arguments, tuple):
            return tuple(self._redact_arguments(value) for value in arguments)
        if isinstance(arguments, list):
            return [self._redact_arguments(value) for value in arguments]
        if isinstance(arguments, dict):
            return {key: self._redact_arguments(value) for key, value in arguments.items()}
        return self._redact_text(arguments) if isinstance(arguments, str) else arguments

    def _redact_text(self, text: str) -> str:
        redacted = text
        for secret in self._secrets:
            redacted = redacted.replace(secret, "[REDACTED]")
        return _SENSITIVE_VALUE_PATTERN.sub(r"\1\2[REDACTED]", redacted)


def configure_logging(log_dir: Path, secrets: Iterable[str]) -> logging.Logger:
    """Configure the application logger with one credential-safe rotating file."""
    target_directory = Path(log_dir)
    target_directory.mkdir(parents=True, exist_ok=True)
    log_path = target_directory / _LOG_FILE_NAME

    logger = logging.getLogger("remote_firewalld_manager")
    logger.setLevel(logging.INFO)
    logger.propagate = False

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

    redaction_filter = SecretRedactionFilter(secrets)
    if existing_handler:
        previous_filter = getattr(existing_handler, "_credential_safe_logging_filter", None)
        if previous_filter:
            existing_handler.removeFilter(previous_filter)
        existing_handler.addFilter(redaction_filter)
        existing_handler._credential_safe_logging_filter = redaction_filter
        return logger

    handler = RotatingFileHandler(
        log_path,
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"))
    handler.addFilter(redaction_filter)
    handler._remote_firewalld_logging_handler = True
    handler._credential_safe_logging_filter = redaction_filter
    logger.addHandler(handler)
    return logger


class ServerLogBuffer:
    """Maintain a bounded, thread-safe in-memory view of per-server log entries."""

    def __init__(self, max_entries: int = 500) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._entries: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=max_entries))
        self._lock = RLock()
        self._formatter = logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

    def append(self, record: logging.LogRecord) -> None:
        server_id = record.server_id if isinstance(getattr(record, "server_id", None), str) else "default"
        entry = self._formatter.format(record)
        with self._lock:
            self._entries[server_id].append(entry)

    def entries(self, server_id: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries.get(server_id, ()))

    def clear(self, server_id: str) -> None:
        with self._lock:
            if server_id in self._entries:
                self._entries[server_id].clear()
