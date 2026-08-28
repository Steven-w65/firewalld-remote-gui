# Task 5 Report: Credential-safe rotating logging

## Status

Completed. Added credential-safe rotating file logging and a bounded, thread-safe per-server log buffer.

## Files

- `app/utils/logging_setup.py`
- `tests/test_logging_setup.py`

## TDD evidence

### RED

Command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest tests/test_logging_setup.py -v -p no:cacheprovider
```

Output: collection failed as intended with `ModuleNotFoundError: No module named 'app.utils.logging_setup'` (`0 items / 1 error`). The requested module did not yet exist.

### GREEN: focused logging suite

Command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest tests/test_logging_setup.py -v -p no:cacheprovider
```

Output: `8 passed in 0.09s`.

### GREEN: pristine foundation suite

Command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -v -p no:cacheprovider
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m py_compile app\utils\logging_setup.py
```

Output: `73 passed in 0.24s`; compilation completed without output.

## Self-review

- `SecretRedactionFilter` copies a log record before rendering and redacts configured non-empty string secrets from direct messages, formatting arguments, and exception text. It also redacts values paired with `password`, `passphrase`, or `credential` keys.
- `configure_logging` installs one UTF-8 `RotatingFileHandler` in the caller-provided directory, with a 2 MiB limit and five backups. Repeated setup replaces the handler's redaction filter instead of adding another application file handler or duplicating log lines.
- No configuration objects are logged or stringified.
- `ServerLogBuffer` uses per-server bounded deques protected by an `RLock`; `entries` returns immutable snapshots and `clear` affects only the selected server's in-memory view.
- Tests cover configured secrets in direct messages, arguments, exception text, defensive key patterns, empty secrets, absence from the rotating file, portable location, idempotence, isolation, bounded history, and concurrent appends.
- `git diff --check` completed with no output. Generated `__pycache__` directories from tests/compilation were verified and removed.

## Concerns

None.

## Fix Round 1

### Root cause

- The original redactor ran only from the rotating file handler. Logging dispatch therefore reached pre-existing handlers before their records were sanitized.
- Mapping values and app configuration dataclasses were passed through to logging's normal string conversion. The fallback expression only matched unquoted, single-token sensitive values.
- `ServerLogBuffer.append` formatted each incoming record without any filter.
- The original rotating handler already used `RotatingFileHandler` correctly; the missing part was behavioral coverage that exercised the rollover path.

### Regression tests added

- `test_filter_redacts_structured_values_without_rendering_app_config_objects`
- `test_filter_redacts_quoted_multi_word_credential_values_in_text`
- `test_configure_logging_redacts_before_preexisting_handlers_receive_records`
- `test_configure_logging_rotates_utf8_content_and_caps_backups_at_five`
- `test_server_log_buffer_redacts_before_storing_entries`

### RED

Command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest tests/test_logging_setup.py -v -p no:cacheprovider
```

Output: `4 failed, 9 passed in 0.73s`.

- Structured mappings emitted nested credential values and full `ServerConfig`/`LoadedConfig` representations.
- Quoted multi-word `password` and `passphrase` values were emitted unchanged.
- The pre-existing handler received `password=multi word password and replacement-secret` before the rotating handler filter ran.
- `ServerLogBuffer(secrets=[...])` was not accepted and the buffer had no independent redaction path.

The new real-rotation regression passed before the code change because `RotatingFileHandler` already performed the required rollover; it is retained to close the coverage gap. It writes seven UTF-8 records that cross the 2 MiB boundary, verifies the active file plus backups `.1` through `.5`, and verifies that `.6` is absent.

### GREEN

Focused command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest tests/test_logging_setup.py -v -p no:cacheprovider
```

Output: `13 passed in 3.75s`.

Full command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -v -p no:cacheprovider
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m py_compile app\utils\logging_setup.py
```

Output: `78 passed in 3.77s`; compilation completed without output.

### Files changed

- `app/utils/logging_setup.py`
- `tests/test_logging_setup.py`

### Self-review

- The configured logger receives one current `SecretRedactionFilter` before dispatch; every handler present during configuration receives that same current filter, and repeated configuration removes previous module filters before adding the replacement.
- Mapping/list/tuple/set values are copied recursively. Sensitive mapping keys are replaced, and any dataclass instance from `app.config` is replaced before its representation can be generated.
- The text fallback recognizes quoted or unquoted sensitive keys and quoted or multi-word values.
- `ServerLogBuffer` accepts optional secrets while retaining zero-argument use. It filters a copy of each record before formatting and storage.
- The rollover test validates contents rather than only inspecting handler configuration.

### Cleanup and concerns

`__pycache__` directories produced by testing and compilation were verified and removed before commit. No remaining concerns.

## Fix Round 2

### Root cause

`_sanitize_value()` and `_contains_app_config()` recursively traversed mappings and sequence values without tracking the active recursion stack. Self-referential message arguments and cyclic exception arguments therefore raised `RecursionError` during logging.

### Regression tests added

- `test_filter_safely_sanitizes_cyclic_mapping_and_list_message_arguments`
- `test_filter_safely_sanitizes_cyclic_exception_arguments`

The tests verify logging completes, configured credentials are redacted, source mapping/list objects remain unchanged, and cyclic paths render the deterministic `[REDACTED CYCLE]` marker.

### RED

Command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest tests/test_logging_setup.py -v -p no:cacheprovider
```

Output: `2 failed, 13 passed in 8.20s`. Both new tests failed with the expected `RecursionError` in the existing recursive implementations; the other logging tests passed.

### GREEN

Focused command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest tests/test_logging_setup.py -v -p no:cacheprovider
```

Output: `15 passed in 4.40s`.

Full pristine command:

```powershell
Set-Location -LiteralPath 'D:\steve\Documents\GitHub\firewalld-remote-gui'
$env:PYTHONPATH = 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python'
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m pytest -v -p no:cacheprovider
& 'C:\Users\steve\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' -m py_compile app\utils\logging_setup.py
```

Output: `80 passed in 5.15s`; compilation completed without output.

### Files changed

- `app/utils/logging_setup.py`
- `tests/test_logging_setup.py`

### Self-review

- `_sanitize_value()` and `_contains_app_config()` now carry an active identity set, add container identities before descending, and remove them in `finally` blocks. This gives recursion-stack semantics: cycles terminate safely while shared acyclic values are processed independently.
- Sanitization returns `[REDACTED CYCLE]` at a cycle edge and never mutates source values. Cyclic exception arguments use the sanitized deterministic representation while preserving existing traceback rendering for non-cyclic exceptions.
- Round-1 credential redaction, app-config suppression, handler filtering, rotating files, and bounded server buffers remain unchanged.

### Cleanup and concerns

Generated `__pycache__` directories were verified and removed after test/compile runs. `git diff --check` completed with no output. No remaining concerns.
