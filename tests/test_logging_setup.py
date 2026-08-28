import logging
import sys
import threading
from logging.handlers import RotatingFileHandler

import pytest

from app.config.models import LoadedConfig, ServerConfig
from app.utils.logging_setup import (
    SecretRedactionFilter,
    ServerLogBuffer,
    configure_logging,
)


def _record(message, *args, server_id="server-a"):
    record = logging.LogRecord("remote_firewalld", logging.INFO, __file__, 1, message, args, None)
    record.server_id = server_id
    return record


class _RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(self.format(record))


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


def test_filter_redacts_structured_values_without_rendering_app_config_objects():
    server = ServerConfig(
        id="server-a",
        name="Production",
        host="firewall.example.test",
        username="admin",
        password="server-password",
    )
    loaded = LoadedConfig(application=object(), servers=(server,))
    record = _record(
        {
            "password": "multi word password",
            "nested": [{"credential": "nested credential"}],
            "server": server,
            "loaded": loaded,
        }
    )

    SecretRedactionFilter([]).filter(record)

    rendered = record.getMessage()
    assert "multi word password" not in rendered
    assert "nested credential" not in rendered
    assert "firewall.example.test" not in rendered
    assert "[REDACTED]" in rendered
    assert "[REDACTED CONFIG]" in rendered


def test_filter_redacts_quoted_multi_word_credential_values_in_text():
    record = _record(
        '{"password": "a multi word password", \'passphrase\': \'open sesame phrase\'}'
    )

    SecretRedactionFilter([]).filter(record)

    message = record.getMessage()
    assert "a multi word password" not in message
    assert "open sesame phrase" not in message
    assert message.count("[REDACTED]") == 2


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


def test_configure_logging_redacts_before_preexisting_handlers_receive_records(
    tmp_path, configured_logger
):
    logger = logging.getLogger("remote_firewalld_manager")
    existing_handler = _RecordingHandler()
    logger.addHandler(existing_handler)
    try:
        configure_logging(tmp_path / "logs", ["top-secret"])
        configure_logging(tmp_path / "logs", ["replacement-secret"])
        logger.error("password=%s and %s", "multi word password", "replacement-secret")
    finally:
        logger.removeHandler(existing_handler)
        existing_handler.close()

    assert len(existing_handler.messages) == 1
    assert "multi word password" not in existing_handler.messages[0]
    assert "replacement-secret" not in existing_handler.messages[0]
    assert "[REDACTED]" in existing_handler.messages[0]


def test_configure_logging_rotates_utf8_content_and_caps_backups_at_five(
    tmp_path, configured_logger
):
    logger = configure_logging(tmp_path / "logs", [])
    payload = "🚀" + ("x" * (2 * 1024 * 1024))
    for _ in range(7):
        logger.info("%s", payload)
    for handler in logger.handlers:
        handler.flush()

    log_file = tmp_path / "logs" / "remote-firewalld-manager.log"
    log_files = [log_file, *(log_file.with_name(f"{log_file.name}.{index}") for index in range(1, 6))]
    assert all(path.exists() for path in log_files)
    assert all("🚀" in path.read_text(encoding="utf-8") for path in log_files)
    assert not log_file.with_name(f"{log_file.name}.6").exists()


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


def test_server_log_buffer_redacts_before_storing_entries():
    buffer = ServerLogBuffer(secrets=["known-secret"])
    buffer.append(_record("password='multi word password' token=%s", "known-secret"))

    entry = buffer.entries("server-a")[0]
    assert "multi word password" not in entry
    assert "known-secret" not in entry
    assert "[REDACTED]" in entry


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
