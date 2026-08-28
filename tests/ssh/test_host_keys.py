import base64
import hashlib
import traceback
from dataclasses import replace
from pathlib import Path

import paramiko
import pytest

from app.ssh import host_keys
from app.ssh.host_keys import HostKeyStore
from app.utils.errors import ChangedHostKeyError, HostKeyStoreError, UnknownHostKeyError


def sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def formatted_exception(error: BaseException) -> str:
    return "".join(traceback.format_exception(error))


def temporary_files(known_hosts: Path) -> list[Path]:
    return list(known_hosts.parent.glob(f".{known_hosts.name}.*.tmp"))


def test_unknown_key_exposes_safe_challenge_without_trusting(tmp_path):
    """Catches an accidental AutoAddPolicy-style trust decision."""
    known_hosts = tmp_path / "known_hosts"
    store = HostKeyStore(known_hosts)
    key = paramiko.RSAKey.generate(1024)

    with pytest.raises(UnknownHostKeyError) as caught:
        store.verify("example.test", 22, key)

    challenge = caught.value.challenge
    assert (challenge.host, challenge.port) == ("example.test", 22)
    assert challenge.algorithm == key.get_name()
    assert challenge.fingerprint_sha256 == sha256_fingerprint(key)
    assert challenge.key == key
    assert "example.test" in str(caught.value)
    assert key.get_base64() not in str(caught.value)
    assert not known_hosts.exists()


def test_challenge_uses_openssh_host_names_for_default_and_custom_ports(tmp_path):
    """Catches a trust record that would not match Paramiko's OpenSSH lookup."""
    store = HostKeyStore(tmp_path / "known_hosts")
    default_key = paramiko.RSAKey.generate(1024)
    custom_key = paramiko.RSAKey.generate(1024)

    store.trust(store.challenge("default.test", 22, default_key))
    store.trust(store.challenge("custom.test", 2222, custom_key))

    loaded = store.load()
    assert loaded.lookup("default.test")[default_key.get_name()] == default_key
    assert loaded.lookup("[custom.test]:2222")[custom_key.get_name()] == custom_key


def test_matching_trusted_key_round_trips(tmp_path):
    """Catches a store that persists a key but cannot later authenticate it."""
    known_hosts = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(1024)

    store = HostKeyStore(known_hosts)
    store.trust(store.challenge("example.test", 2222, key))

    HostKeyStore(known_hosts).verify("example.test", 2222, key)


def test_changed_key_reports_only_safe_expected_and_actual_fingerprints(tmp_path):
    """Catches acceptance of a replacement key or leakage of public-key material."""
    known_hosts = tmp_path / "known_hosts"
    original = paramiko.RSAKey.generate(1024)
    replacement = paramiko.RSAKey.generate(1024)
    store = HostKeyStore(known_hosts)
    store.trust(store.challenge("example.test", 22, original))

    with pytest.raises(ChangedHostKeyError) as caught:
        store.verify("example.test", 22, replacement)

    error = caught.value
    assert error.host == "example.test"
    assert error.port == 22
    assert error.expected_fingerprint == sha256_fingerprint(original)
    assert error.actual_fingerprint == sha256_fingerprint(replacement)
    assert error.expected_fingerprint in str(error)
    assert error.actual_fingerprint in str(error)
    assert original.get_base64() not in str(error)
    assert replacement.get_base64() not in str(error)


def test_corrupt_known_hosts_is_reported_safely_without_replacing_data(tmp_path):
    """Catches trust persistence that overwrites an unreadable existing trust file."""
    known_hosts = tmp_path / "known_hosts"
    corrupt_contents = "not a valid known hosts entry\n"
    known_hosts.write_text(corrupt_contents, encoding="utf-8")
    store = HostKeyStore(known_hosts)
    key = paramiko.RSAKey.generate(1024)

    with pytest.raises(HostKeyStoreError) as caught:
        store.trust(store.challenge("example.test", 22, key))

    traceback_text = formatted_exception(caught.value)
    assert known_hosts.read_text(encoding="utf-8") == corrupt_contents
    assert corrupt_contents.strip() not in traceback_text
    assert key.get_base64() not in traceback_text


def test_direct_trust_rejects_a_changed_same_algorithm_key_without_replacing_bytes(tmp_path):
    """Catches an accidental replacement path exposed through ``trust`` itself."""
    known_hosts = tmp_path / "known_hosts"
    store = HostKeyStore(known_hosts)
    original = paramiko.RSAKey.generate(1024)
    replacement = paramiko.RSAKey.generate(1024)
    store.trust(store.challenge("example.test", 22, original))
    original_bytes = known_hosts.read_bytes()

    with pytest.raises(ChangedHostKeyError):
        store.trust(store.challenge("example.test", 22, replacement))

    assert known_hosts.read_bytes() == original_bytes


@pytest.mark.parametrize(
    "tampered",
    [
        lambda challenge: replace(challenge, fingerprint_sha256="SHA256:tampered"),
        lambda challenge: replace(challenge, algorithm="ssh-ed25519"),
    ],
)
def test_inconsistent_challenge_is_rejected_without_creating_trust(tmp_path, tampered):
    """Catches persistence of a challenge whose displayed data no longer matches its key."""
    known_hosts = tmp_path / "known_hosts"
    store = HostKeyStore(known_hosts)
    key = paramiko.RSAKey.generate(1024)

    with pytest.raises(HostKeyStoreError) as caught:
        store.trust(tampered(store.challenge("example.test", 22, key)))

    assert key.get_base64() not in formatted_exception(caught.value)
    assert not known_hosts.exists()


def test_persistence_preserves_existing_hosts_and_multiple_key_algorithms(tmp_path):
    """Catches a rewrite that silently drops an existing host or key algorithm."""
    known_hosts = tmp_path / "known_hosts"
    store = HostKeyStore(known_hosts)
    rsa_key = paramiko.RSAKey.generate(1024)
    ecdsa_key = paramiko.ECDSAKey.generate(bits=256)
    other_key = paramiko.RSAKey.generate(1024)

    store.trust(store.challenge("example.test", 22, rsa_key))
    store.trust(store.challenge("example.test", 22, ecdsa_key))
    store.trust(store.challenge("other.test", 2222, other_key))

    reloaded = HostKeyStore(known_hosts)
    reloaded.verify("example.test", 22, rsa_key)
    reloaded.verify("example.test", 22, ecdsa_key)
    reloaded.verify("other.test", 2222, other_key)


def test_trust_replaces_from_a_temporary_file_in_the_known_hosts_directory(tmp_path, monkeypatch):
    """Catches cross-directory staging, which is not an atomic replacement guarantee."""
    known_hosts = tmp_path / "known_hosts"
    observed: dict[str, Path] = {}
    real_replace = host_keys.os.replace

    def recording_replace(source, destination):
        observed["source"] = Path(source)
        observed["destination"] = Path(destination)
        real_replace(source, destination)

    monkeypatch.setattr(host_keys.os, "replace", recording_replace)
    key = paramiko.RSAKey.generate(1024)
    HostKeyStore(known_hosts).trust(HostKeyStore(known_hosts).challenge("example.test", 22, key))

    assert observed["source"].parent == known_hosts.parent
    assert observed["destination"] == known_hosts
    assert not temporary_files(known_hosts)


@pytest.mark.parametrize("failure", ["close", "save", "replace"])
def test_persistence_failure_keeps_original_cleans_temp_and_hides_unsafe_details(
    tmp_path, monkeypatch, failure
):
    """Catches partial trust writes and unsafe OS/Paramiko exception chaining."""
    known_hosts = tmp_path / "known_hosts"
    store = HostKeyStore(known_hosts)
    original = paramiko.RSAKey.generate(1024)
    candidate = paramiko.RSAKey.generate(1024)
    store.trust(store.challenge("existing.test", 22, original))
    original_bytes = known_hosts.read_bytes()
    unsafe_text = f"{failure}-failure-SENTINEL"

    if failure == "close":
        real_close = host_keys.os.close
        close_attempts = 0

        def fail_first_close(descriptor):
            nonlocal close_attempts
            close_attempts += 1
            if close_attempts == 1:
                raise OSError(unsafe_text)
            real_close(descriptor)

        monkeypatch.setattr(host_keys.os, "close", fail_first_close)
    elif failure == "save":
        def fail_save(self, filename):
            raise OSError(unsafe_text)

        monkeypatch.setattr(paramiko.HostKeys, "save", fail_save)
    else:
        def fail_replace(source, destination):
            raise OSError(unsafe_text)

        monkeypatch.setattr(host_keys.os, "replace", fail_replace)

    with pytest.raises(HostKeyStoreError) as caught:
        store.trust(store.challenge("candidate.test", 22, candidate))

    traceback_text = formatted_exception(caught.value)
    assert known_hosts.read_bytes() == original_bytes
    assert not temporary_files(known_hosts)
    assert unsafe_text not in traceback_text
    assert candidate.get_base64() not in traceback_text
