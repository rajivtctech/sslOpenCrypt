"""
tests/test_vault.py — Tests for modules/vault/controller.py (Key Vault)
"""

import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_vault_state():
    """Reset the vault module singleton state between tests."""
    import modules.vault.controller as vc
    vc._vault_data = None
    vc._vault_passphrase = None


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_returns_32_bytes(self):
        from modules.vault.controller import _derive_key
        key = _derive_key("test_passphrase", os.urandom(32))
        assert len(key) == 32

    def test_different_salt_different_key(self):
        from modules.vault.controller import _derive_key
        salt1 = os.urandom(32)
        salt2 = os.urandom(32)
        k1 = _derive_key("password", salt1)
        k2 = _derive_key("password", salt2)
        assert k1 != k2

    def test_same_inputs_same_key(self):
        from modules.vault.controller import _derive_key
        salt = os.urandom(32)
        k1 = _derive_key("password", salt)
        k2 = _derive_key("password", salt)
        assert k1 == k2

    def test_different_passphrase_different_key(self):
        from modules.vault.controller import _derive_key
        salt = os.urandom(32)
        k1 = _derive_key("password1", salt)
        k2 = _derive_key("password2", salt)
        assert k1 != k2


# ---------------------------------------------------------------------------
# Encrypt / Decrypt payload
# ---------------------------------------------------------------------------

class TestEncryptDecryptPayload:
    def test_round_trip(self):
        from modules.vault.controller import _encrypt_payload, _decrypt_payload
        payload = '{"version":1,"entries":[]}'
        blob = _encrypt_payload(payload, "secret")
        result = _decrypt_payload(blob, "secret")
        assert result == payload

    def test_wrong_passphrase_raises(self):
        from modules.vault.controller import _encrypt_payload, _decrypt_payload
        blob = _encrypt_payload('{"test": true}', "correct")
        with pytest.raises(ValueError, match="[Aa]uthentication|[Pp]assphrase|corrupt"):
            _decrypt_payload(blob, "wrong")

    def test_magic_bytes(self):
        from modules.vault.controller import _encrypt_payload, VAULT_MAGIC
        blob = _encrypt_payload("{}", "pw")
        assert blob[:4] == VAULT_MAGIC

    def test_bad_magic_raises(self):
        from modules.vault.controller import _decrypt_payload
        bad = b"XXXX" + bytes(100)
        with pytest.raises(ValueError, match="magic|valid"):
            _decrypt_payload(bad, "pw")

    def test_too_short_raises(self):
        from modules.vault.controller import _decrypt_payload
        with pytest.raises(ValueError, match="short|corrupt"):
            _decrypt_payload(b"SSVC\x01" + bytes(10), "pw")

    def test_unicode_payload_round_trips(self):
        from modules.vault.controller import _encrypt_payload, _decrypt_payload
        payload = '{"name": "José García — résumé"}'
        blob = _encrypt_payload(payload, "pw")
        assert _decrypt_payload(blob, "pw") == payload

    def test_fresh_encryption_different_blobs(self):
        """Two encryptions of same data produce different blobs (random nonce/salt)."""
        from modules.vault.controller import _encrypt_payload
        payload = '{"test": 1}'
        b1 = _encrypt_payload(payload, "pw")
        b2 = _encrypt_payload(payload, "pw")
        assert b1 != b2


# ---------------------------------------------------------------------------
# Vault lifecycle (create / unlock / lock)
# ---------------------------------------------------------------------------

class TestVaultLifecycle:
    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def test_create_and_unlock(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, unlock_vault, is_unlocked, lock_vault
        create_vault("mypassword")
        assert is_unlocked()
        lock_vault()
        assert not is_unlocked()
        unlock_vault("mypassword")
        assert is_unlocked()

    def test_unlock_wrong_passphrase(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, unlock_vault
        create_vault("correct")
        from modules.vault.controller import lock_vault
        lock_vault()
        with pytest.raises(ValueError):
            unlock_vault("wrong")

    def test_unlock_no_vault(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import unlock_vault
        with pytest.raises(FileNotFoundError):
            unlock_vault("pw")

    def test_vault_file_created(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault
        create_vault("pw")
        vault_file = tmp_path / "vault.enc"
        assert vault_file.exists()
        assert vault_file.stat().st_size > 0

    def test_vault_file_permissions(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault
        create_vault("pw")
        vault_file = tmp_path / "vault.enc"
        mode = oct(vault_file.stat().st_mode & 0o777)
        assert mode == oct(0o600), f"Expected 0o600, got {mode}"


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------

SAMPLE_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7o4qne60TB3wo
-----END PRIVATE KEY-----"""


class TestVaultCRUD:
    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def _setup(self, monkeypatch, tmp_path):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault
        create_vault("pw")

    def test_add_and_list_key(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import add_key, list_keys
        eid = add_key("Test Key", "RSA-2048", SAMPLE_PEM, tags=["test"], comment="unit test")
        assert isinstance(eid, str)
        # UUID format
        uuid.UUID(eid)
        entries = list_keys()
        assert len(entries) == 1
        assert entries[0]["name"] == "Test Key"
        assert entries[0]["algorithm"] == "RSA-2048"
        assert "pem" not in entries[0]

    def test_get_key_pem(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import add_key, get_key_pem
        eid = add_key("My Key", "ECDSA-P256", SAMPLE_PEM)
        pem = get_key_pem(eid)
        assert pem == SAMPLE_PEM.strip()

    def test_get_key_pem_not_found(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import get_key_pem
        with pytest.raises(KeyError):
            get_key_pem("nonexistent-id")

    def test_remove_key(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import add_key, remove_key, list_keys
        eid = add_key("Temp Key", "Ed25519", SAMPLE_PEM)
        assert len(list_keys()) == 1
        remove_key(eid)
        assert len(list_keys()) == 0

    def test_remove_nonexistent_key(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import remove_key
        with pytest.raises(KeyError):
            remove_key("does-not-exist")

    def test_multiple_keys(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import add_key, list_keys
        add_key("Key A", "RSA-2048", SAMPLE_PEM)
        add_key("Key B", "ECDSA-P256", SAMPLE_PEM)
        add_key("Key C", "Ed25519", SAMPLE_PEM)
        assert len(list_keys()) == 3

    def test_update_key_metadata(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import add_key, update_key_metadata, list_keys
        eid = add_key("Original", "RSA-2048", SAMPLE_PEM, tags=["old"], comment="before")
        update_key_metadata(eid, name="Updated", tags=["new"], comment="after")
        entries = list_keys()
        e = entries[0]
        assert e["name"] == "Updated"
        assert e["tags"] == ["new"]
        assert e["comment"] == "after"

    def test_update_nonexistent_raises(self, tmp_path, monkeypatch):
        self._setup(monkeypatch, tmp_path)
        from modules.vault.controller import update_key_metadata
        with pytest.raises(KeyError):
            update_key_metadata("bad-id", name="X")

    def test_operations_require_unlock(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import add_key, list_keys, remove_key
        # Vault not created/unlocked
        with pytest.raises(RuntimeError, match="locked"):
            add_key("X", "RSA", SAMPLE_PEM)
        with pytest.raises(RuntimeError, match="locked"):
            list_keys()


# ---------------------------------------------------------------------------
# Export key to file
# ---------------------------------------------------------------------------

class TestExportKey:
    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def test_export_key_to_file(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, add_key, export_key_to_file
        create_vault("pw")
        eid = add_key("Export Test", "ECDSA-P256", SAMPLE_PEM)
        out = str(tmp_path / "exported.pem")
        export_key_to_file(eid, out)
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "PRIVATE KEY" in content
        # Check permissions
        mode = oct(Path(out).stat().st_mode & 0o777)
        assert mode == oct(0o600)

    def test_import_key_from_file(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, import_key_from_file, list_keys, get_key_pem
        create_vault("pw")
        pem_file = tmp_path / "test.pem"
        pem_file.write_text(SAMPLE_PEM)
        eid = import_key_from_file(str(pem_file), "Imported Key", "RSA-2048")
        assert len(list_keys()) == 1
        assert "PRIVATE KEY" in get_key_pem(eid)


# ---------------------------------------------------------------------------
# Change passphrase
# ---------------------------------------------------------------------------

class TestChangePassphrase:
    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def test_change_passphrase(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, add_key, change_passphrase, lock_vault, unlock_vault, list_keys
        create_vault("old_pass")
        add_key("Key", "ECDSA-P256", SAMPLE_PEM)
        change_passphrase("old_pass", "new_pass")
        lock_vault()
        # Old passphrase should fail
        with pytest.raises(ValueError):
            unlock_vault("old_pass")
        # New passphrase should work and data preserved
        unlock_vault("new_pass")
        assert len(list_keys()) == 1

    def test_change_passphrase_wrong_old(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, change_passphrase
        create_vault("correct")
        with pytest.raises(ValueError, match="[Ii]ncorrect|[Ww]rong"):
            change_passphrase("wrong", "new")


# ---------------------------------------------------------------------------
# Vault stats
# ---------------------------------------------------------------------------

class TestVaultStats:
    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def test_stats_empty_vault(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, vault_stats
        create_vault("pw")
        stats = vault_stats()
        assert stats["total_keys"] == 0
        assert isinstance(stats["algorithms"], dict)
        assert stats["vault_size_bytes"] > 0

    def test_stats_with_keys(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, add_key, vault_stats
        create_vault("pw")
        add_key("A", "RSA-2048", SAMPLE_PEM)
        add_key("B", "RSA-2048", SAMPLE_PEM)
        add_key("C", "ECDSA-P256", SAMPLE_PEM)
        stats = vault_stats()
        assert stats["total_keys"] == 3
        assert stats["algorithms"]["RSA-2048"] == 2
        assert stats["algorithms"]["ECDSA-P256"] == 1

    def test_stats_requires_unlock(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import vault_stats
        with pytest.raises(RuntimeError, match="locked"):
            vault_stats()


# ---------------------------------------------------------------------------
# Persistence (unlock after lock, data survives)
# ---------------------------------------------------------------------------

class TestPersistence:
    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def test_data_persists_after_lock_unlock(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        from modules.vault.controller import create_vault, add_key, lock_vault, unlock_vault, list_keys, get_key_pem
        create_vault("pw")
        eid = add_key("Persist Test", "Ed25519", SAMPLE_PEM, tags=["persist"], comment="survives relock")
        lock_vault()
        unlock_vault("pw")
        entries = list_keys()
        assert len(entries) == 1
        assert entries[0]["name"] == "Persist Test"
        assert entries[0]["tags"] == ["persist"]
        assert "PRIVATE KEY" in get_key_pem(eid)


# ---------------------------------------------------------------------------
# Helper to monkeypatch vault path
# ---------------------------------------------------------------------------

def _patch_vault_path(monkeypatch, tmp_path: Path):
    """Redirect vault file to tmp_path for test isolation."""
    import modules.vault.controller as vc

    def mock_vault_path():
        tmp_path.mkdir(exist_ok=True)
        return tmp_path / "vault.enc"

    monkeypatch.setattr(vc, "_vault_path", mock_vault_path)
