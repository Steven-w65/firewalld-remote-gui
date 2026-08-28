import logging
import sys
import threading
from logging.handlers import RotatingFileHandler

import pytest

from app.utils.logging_setup import (
    SecretRedactionFilter,
    ServerLogBuffer,
    configure_logging,
)


def _record(message, *args, server_id="server-a"):
    record = logging.LogRecord("remote_firewalld", logging.INFO, __file__, 1, message, args, None)
    record.server_id = server_id
    return record


@pytest.fixture
def configured_logger():
    logger = logging.getLogger("remote_firewalld_manager")
    for handler in logger.handlers[:]:
        if getattr(handler, "_remote_firewalld_logging_handler", False):
            logger.removeHandler(handler)
            handler.close()
    yield logger
    for handler in logger.handlers[:]:
        if getattr(handler, "_remote_firewalld_logging_handler", False):
            logger.removeHandler(handler)
            handler.close()


def test_filter_redacts_message_arguments_and_exception_text():
    try:
        raise RuntimeError("top-secret")
    except RuntimeError:
        record = logging.LogRecord(
            "app",
            logging.ERROR,
            __file__,
            1,
            "login top-secret %s",
            ("top-secret",),
            sys.exc_info(),
        )

    SecretRedactionFilter(["top-secret"]).filter(record)
    rendered = logging.Formatter("%(message)s\n%(exc_text)s").format(record)

    assert "top-secret" not in record.getMessage()
    assert "top-secret" not in rendered
    assert "[REDACTED]" in rendered


def test_filter_redacts_password_passphrase_and_credential_values():
    record = _record(
        "password=hunter2 passphrase: open-sesame credential='api-token' unchanged=value"
    )

    SecretRedactionFilter([]).filter(record)

    message = record.getMessage()
    assert "hunter2" not in message
    assert "open-sesame" not in message
    assert "api-token" not in message
    assert "unchanged=value" in message
    assert message.count("[REDACTED]") == 3


def test_filter_ignores_empty_secrets():
    record = _record("connected to %s", "firewalld")

    SecretRedactionFilter(["", "  "]).filter(record)

    assert record.getMessage() == "connected to firewalld"


def test_configure_logging_creates_one_rotating_file_inside_requested_directory(
    tmp_path, configured_logger
):
    log_dir = tmp_path / "logs"
    logger = configure_logging(log_dir, ["top-secret"])
    logger.info("message contains top-secret")
    logger.info("connected with %s", "top-secret")
    try:
        raise RuntimeError("top-secret")
    except RuntimeError:
        logger.exception("request failed with top-secret")
    for handler in logger.handlers:
        handler.flush()

    log_file = log_dir / "remote-firewalld-manager.log"
    assert log_file.exists()
    assert not (tmp_path / "remote-firewalld-manager.log").exists()
    assert "top-secret" not in log_file.read_text(encoding="utf-8")
    assert "[REDACTED]" in log_file.read_text(encoding="utf-8")
    handler = next(handler for handler in logger.handlers if hasattr(handler, "maxBytes"))
    assert handler.maxBytes == 2 * 1024 * 1024
    assert handler.backupCount == 5


def test_configure_logging_is_idempotent_and_does_not_duplicate_log_lines(
    tmp_path, configured_logger
):
    logger = configure_logging(tmp_path / "logs", [])
    logger = configure_logging(tmp_path / "logs", [])
    logger.info("one line")
    for handler in logger.handlers:
        handler.flush()

    assert sum(isinstance(handler, RotatingFileHandler) for handler in logger.handlers) == 1
    contents = (tmp_path / "logs" / "remote-firewalld-manager.log").read_text(encoding="utf-8")
    assert contents.count("one line") == 1


def test_server_log_buffer_appends_formatted_entries_and_clears_one_server():
    buffer = ServerLogBuffer(max_entries=3)
    buffer.append(_record("first", server_id="server-a"))
    buffer.append(_record("second", server_id="server-b"))

    entries = buffer.entries("server-a")
    buffer.clear("server-a")

    assert len(entries) == 1
    assert "INFO" in entries[0]
    assert "remote_firewalld" in entries[0]
    assert "first" in entries[0]
    assert buffer.entries("server-a") == ()
    assert len(buffer.entries("server-b")) == 1
    assert "second" in buffer.entries("server-b")[0]


def test_server_log_buffer_keeps_only_its_bounded_history():
    buffer = ServerLogBuffer(max_entries=2)
    for message in ("first", "second", "third"):
        buffer.append(_record(message))

    entries = buffer.entries("server-a")

    assert len(entries) == 2
    assert "first" not in "\n".join(entries)
    assert "second" in entries[0]
    assert "third" in entries[1]


def test_server_log_buffer_handles_concurrent_appends_without_losing_entries():
    buffer = ServerLogBuffer(max_entries=800)

    def append_range(worker_number):
        for index in range(100):
            buffer.append(_record(f"worker-{worker_number}-{index}"))

    threads = [threading.Thread(target=append_range, args=(worker_number,)) for worker_number in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    entries = buffer.entries("server-a")
    assert len(entries) == 800
    assert all("INFO" in entry for entry in entries)
