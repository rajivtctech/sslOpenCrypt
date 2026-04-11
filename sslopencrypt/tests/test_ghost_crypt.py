"""
tests/test_ghost_crypt.py — Unit tests for Ghost Crypt (Section 8B).

Tests cover:
  - Container creation and recovery (file-based and bytes-based)
  - Both supported ciphers: AES-256-GCM and ChaCha20-Poly1305
  - Binary layout verification (salt + nonce + ciphertext, no header)
  - Wrong passphrase returns failure with auth error
  - Truncated / corrupt container detection
  - Containers are indistinguishable from random (no known header bytes)
  - Output file permissions (0o600)
  - Round-trip with various payload sizes (empty, 1 byte, 1 KiB, 64 KiB)
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.symmetric.ghost_crypt import (
    GHOST_OVERHEAD,
    GHOST_SALT_LEN,
    GHOST_NONCE_LEN,
    GHOST_TAG_LEN,
    SUPPORTED_CIPHERS,
    create_container,
    create_container_from_bytes,
    open_container,
    open_container_from_bytes,
    _derive_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_file(content: bytes = b"") -> str:
    fd, path = tempfile.mkstemp()
    os.close(fd)
    if content:
        Path(path).write_bytes(content)
    return path


def _tmp_output() -> str:
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path


PASSPHRASE = "correct-horse-battery-staple"
WRONG_PASS = "wrong-passphrase-xyz"


# ---------------------------------------------------------------------------
# _derive_key
# ---------------------------------------------------------------------------

class TestDeriveKey:
    def test_returns_32_bytes(self):
        salt = os.urandom(32)
        key = _derive_key(PASSPHRASE, salt)
        assert len(key) == 32

    def test_different_salt_different_key(self):
        s1, s2 = os.urandom(32), os.urandom(32)
        assert _derive_key(PASSPHRASE, s1) != _derive_key(PASSPHRASE, s2)

    def test_same_inputs_reproducible(self):
        salt = os.urandom(32)
        assert _derive_key(PASSPHRASE, salt) == _derive_key(PASSPHRASE, salt)

    def test_different_passphrase_different_key(self):
        salt = os.urandom(32)
        assert _derive_key("pass1", salt) != _derive_key("pass2", salt)

    def test_key_is_bytes(self):
        key = _derive_key(PASSPHRASE, os.urandom(32))
        assert isinstance(key, bytes)


# ---------------------------------------------------------------------------
# Bytes API — AES-256-GCM
# ---------------------------------------------------------------------------

class TestBytesApiAESGCM:
    CIPHER = "AES-256-GCM"

    def test_round_trip_simple(self):
        plaintext = b"Hello, Ghost Crypt!"
        r_enc = create_container_from_bytes(plaintext, PASSPHRASE, self.CIPHER)
        assert r_enc.success, r_enc.stderr
        container = r_enc.parsed["container_bytes"]

        r_dec = open_container_from_bytes(container, PASSPHRASE, self.CIPHER)
        assert r_dec.success, r_dec.stderr
        assert r_dec.parsed["plaintext_bytes"] == plaintext

    def test_container_size_is_overhead_plus_payload(self):
        payload = b"X" * 100
        r = create_container_from_bytes(payload, PASSPHRASE, self.CIPHER)
        assert r.success
        container = r.parsed["container_bytes"]
        assert len(container) == len(payload) + GHOST_OVERHEAD

    def test_overhead_constant(self):
        assert GHOST_OVERHEAD == GHOST_SALT_LEN + GHOST_NONCE_LEN + GHOST_TAG_LEN
        assert GHOST_OVERHEAD == 60

    def test_no_magic_bytes(self):
        """Container must not start with any recognisable magic sequence."""
        payloads = [b"test data", b"\x00" * 16, os.urandom(64)]
        for p in payloads:
            r = create_container_from_bytes(p, PASSPHRASE, self.CIPHER)
            container = r.parsed["container_bytes"]
            # Should NOT start with common magic bytes
            assert not container.startswith(b"\x89PNG")
            assert not container.startswith(b"PK")
            assert not container.startswith(b"MZ")
            assert not container.startswith(b"\x7fELF")

    def test_two_encryptions_different_blobs(self):
        """Each encryption produces a different container (random salt+nonce)."""
        plaintext = b"same data"
        r1 = create_container_from_bytes(plaintext, PASSPHRASE, self.CIPHER)
        r2 = create_container_from_bytes(plaintext, PASSPHRASE, self.CIPHER)
        assert r1.parsed["container_bytes"] != r2.parsed["container_bytes"]

    def test_wrong_passphrase_fails(self):
        r_enc = create_container_from_bytes(b"secret", PASSPHRASE, self.CIPHER)
        container = r_enc.parsed["container_bytes"]
        r_dec = open_container_from_bytes(container, WRONG_PASS, self.CIPHER)
        assert not r_dec.success
        assert "authentication" in r_dec.stderr.lower() or "wrong" in r_dec.stderr.lower()

    def test_truncated_container_fails(self):
        r = create_container_from_bytes(b"data", PASSPHRASE, self.CIPHER)
        container = r.parsed["container_bytes"]
        # Truncate to below minimum
        r_dec = open_container_from_bytes(container[:10], PASSPHRASE, self.CIPHER)
        assert not r_dec.success

    def test_empty_payload(self):
        r_enc = create_container_from_bytes(b"", PASSPHRASE, self.CIPHER)
        assert r_enc.success
        r_dec = open_container_from_bytes(r_enc.parsed["container_bytes"], PASSPHRASE, self.CIPHER)
        assert r_dec.success
        assert r_dec.parsed["plaintext_bytes"] == b""

    def test_one_byte_payload(self):
        r_enc = create_container_from_bytes(b"\xff", PASSPHRASE, self.CIPHER)
        assert r_enc.success
        r_dec = open_container_from_bytes(r_enc.parsed["container_bytes"], PASSPHRASE, self.CIPHER)
        assert r_dec.success
        assert r_dec.parsed["plaintext_bytes"] == b"\xff"

    def test_1kib_payload(self):
        payload = os.urandom(1024)
        r_enc = create_container_from_bytes(payload, PASSPHRASE, self.CIPHER)
        assert r_enc.success
        r_dec = open_container_from_bytes(r_enc.parsed["container_bytes"], PASSPHRASE, self.CIPHER)
        assert r_dec.success
        assert r_dec.parsed["plaintext_bytes"] == payload

    def test_64kib_payload(self):
        payload = os.urandom(65536)
        r_enc = create_container_from_bytes(payload, PASSPHRASE, self.CIPHER)
        assert r_enc.success
        r_dec = open_container_from_bytes(r_enc.parsed["container_bytes"], PASSPHRASE, self.CIPHER)
        assert r_dec.success
        assert r_dec.parsed["plaintext_bytes"] == payload

    def test_bit_flip_fails_authentication(self):
        r = create_container_from_bytes(b"sensitive data", PASSPHRASE, self.CIPHER)
        container = bytearray(r.parsed["container_bytes"])
        container[-1] ^= 0xFF  # flip last byte of GCM tag
        r_dec = open_container_from_bytes(bytes(container), PASSPHRASE, self.CIPHER)
        assert not r_dec.success

    def test_parsed_fields_present(self):
        r = create_container_from_bytes(b"data", PASSPHRASE, self.CIPHER)
        assert "salt_hex" in r.parsed
        assert "nonce_hex" in r.parsed
        assert "overhead_bytes" in r.parsed
        assert r.parsed["overhead_bytes"] == GHOST_OVERHEAD
        assert r.parsed["cipher"] == self.CIPHER

    def test_unsupported_cipher_fails(self):
        r = create_container_from_bytes(b"data", PASSPHRASE, "RC4")
        assert not r.success
        assert "unsupported" in r.stderr.lower()

    def test_open_unsupported_cipher_fails(self):
        r = create_container_from_bytes(b"data", PASSPHRASE, self.CIPHER)
        container = r.parsed["container_bytes"]
        r_dec = open_container_from_bytes(container, PASSPHRASE, "3DES-CBC")
        assert not r_dec.success


# ---------------------------------------------------------------------------
# Bytes API — ChaCha20-Poly1305
# ---------------------------------------------------------------------------

class TestBytesApiChaCha20:
    CIPHER = "ChaCha20-Poly1305"

    def test_round_trip(self):
        plaintext = b"ChaCha20 Ghost Crypt test"
        r_enc = create_container_from_bytes(plaintext, PASSPHRASE, self.CIPHER)
        assert r_enc.success
        r_dec = open_container_from_bytes(r_enc.parsed["container_bytes"], PASSPHRASE, self.CIPHER)
        assert r_dec.success
        assert r_dec.parsed["plaintext_bytes"] == plaintext

    def test_container_size(self):
        payload = b"Y" * 200
        r = create_container_from_bytes(payload, PASSPHRASE, self.CIPHER)
        assert len(r.parsed["container_bytes"]) == len(payload) + GHOST_OVERHEAD

    def test_wrong_passphrase(self):
        r = create_container_from_bytes(b"secret", PASSPHRASE, self.CIPHER)
        container = r.parsed["container_bytes"]
        r_dec = open_container_from_bytes(container, WRONG_PASS, self.CIPHER)
        assert not r_dec.success

    def test_different_from_aes_gcm(self):
        """ChaCha20 and AES-GCM produce different containers for same plaintext."""
        plaintext = b"compare ciphers"
        r_aes = create_container_from_bytes(plaintext, PASSPHRASE, "AES-256-GCM")
        r_cha = create_container_from_bytes(plaintext, PASSPHRASE, self.CIPHER)
        assert r_aes.parsed["container_bytes"] != r_cha.parsed["container_bytes"]

    def test_cross_cipher_open_fails(self):
        """Container created with ChaCha20 cannot be opened with AES-GCM and vice versa."""
        r = create_container_from_bytes(b"data", PASSPHRASE, self.CIPHER)
        container = r.parsed["container_bytes"]
        r_dec = open_container_from_bytes(container, PASSPHRASE, "AES-256-GCM")
        assert not r_dec.success


# ---------------------------------------------------------------------------
# Supported ciphers list
# ---------------------------------------------------------------------------

class TestSupportedCiphers:
    def test_aes_gcm_present(self):
        assert "AES-256-GCM" in SUPPORTED_CIPHERS

    def test_chacha_present(self):
        assert "ChaCha20-Poly1305" in SUPPORTED_CIPHERS

    def test_no_deprecated_ciphers(self):
        for c in SUPPORTED_CIPHERS:
            assert "3DES" not in c
            assert "DES-CBC" not in c
            assert "RC4" not in c


# ---------------------------------------------------------------------------
# File API
# ---------------------------------------------------------------------------

class TestFileApi:
    def test_round_trip_file(self, tmp_path):
        plaintext = b"File-based Ghost Crypt round-trip test."
        inp = tmp_path / "plain.bin"
        container = tmp_path / "ghost.bin"
        recovered = tmp_path / "recovered.bin"

        inp.write_bytes(plaintext)

        r_enc = create_container(str(inp), str(container), PASSPHRASE)
        assert r_enc.success, r_enc.stderr
        assert container.exists()

        r_dec = open_container(str(container), str(recovered), PASSPHRASE)
        assert r_dec.success, r_dec.stderr
        assert recovered.read_bytes() == plaintext

    def test_output_permissions(self, tmp_path):
        inp = tmp_path / "plain.bin"
        inp.write_bytes(b"permission test")
        container = tmp_path / "ghost.bin"

        r = create_container(str(inp), str(container), PASSPHRASE)
        assert r.success
        mode = oct(container.stat().st_mode)[-3:]
        assert mode == "600"

    def test_wrong_passphrase_file(self, tmp_path):
        inp = tmp_path / "plain.bin"
        inp.write_bytes(b"secret content")
        container = tmp_path / "ghost.bin"
        out = tmp_path / "out.bin"

        create_container(str(inp), str(container), PASSPHRASE)
        r = open_container(str(container), str(out), WRONG_PASS)
        assert not r.success

    def test_missing_input_file(self, tmp_path):
        r = create_container(str(tmp_path / "nonexistent.bin"), str(tmp_path / "out.bin"), PASSPHRASE)
        assert not r.success

    def test_chacha_round_trip_file(self, tmp_path):
        plaintext = b"ChaCha20 file test" * 10
        inp = tmp_path / "plain.bin"
        container = tmp_path / "ghost.bin"
        recovered = tmp_path / "rec.bin"
        inp.write_bytes(plaintext)

        r_enc = create_container(str(inp), str(container), PASSPHRASE, cipher="ChaCha20-Poly1305")
        assert r_enc.success
        r_dec = open_container(str(container), str(recovered), PASSPHRASE, cipher="ChaCha20-Poly1305")
        assert r_dec.success
        assert recovered.read_bytes() == plaintext

    def test_container_has_no_magic_header(self, tmp_path):
        inp = tmp_path / "data.bin"
        inp.write_bytes(b"test payload")
        container = tmp_path / "ghost.bin"
        create_container(str(inp), str(container), PASSPHRASE)
        data = container.read_bytes()
        assert len(data) >= GHOST_OVERHEAD
        # First 4 bytes should not be common magic
        assert data[:4] not in (b"\x89PNG", b"PK\x03\x04", b"MZ\x00\x00", b"\x7fELF")

    def test_large_file(self, tmp_path):
        payload = os.urandom(128 * 1024)  # 128 KiB
        inp = tmp_path / "large.bin"
        container = tmp_path / "ghost.bin"
        out = tmp_path / "out.bin"
        inp.write_bytes(payload)

        r_enc = create_container(str(inp), str(container), PASSPHRASE)
        assert r_enc.success
        r_dec = open_container(str(container), str(out), PASSPHRASE)
        assert r_dec.success
        assert out.read_bytes() == payload
