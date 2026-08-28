import base64
import hashlib

import paramiko
import pytest

from app.ssh.host_keys import HostKeyStore
from app.utils.errors import ChangedHostKeyError, HostKeyStoreError, UnknownHostKeyError


def sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


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

    assert known_hosts.read_text(encoding="utf-8") == corrupt_contents
    assert corrupt_contents.strip() not in str(caught.value)
    assert key.get_base64() not in str(caught.value)
