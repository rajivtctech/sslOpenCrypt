"""
tests/test_cli.py — Tests for cli/main.py (headless batch/JSON mode)

Tests invoke the CLI functions directly (not via subprocess) for speed,
but exercise the full controller → executor → openssl pipeline.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# Import CLI handler functions directly
from cli.main import (
    cmd_hash, cmd_keygen, cmd_encrypt, cmd_decrypt,
    cmd_sign, cmd_verify, cmd_random, cmd_version,
    _result_to_dict,
)


# ---------------------------------------------------------------------------
# Minimal args stub (mirrors argparse Namespace)
# ---------------------------------------------------------------------------

class _Args:
    """Minimal argparse.Namespace stub for CLI handler testing."""
    def __init__(self, **kwargs):
        defaults = {
            "mode": None, "algorithm": None, "cipher": None,
            "file": None, "text": None, "output": None,
            "key": None, "cert": None, "signature": None,
            "passphrase": None, "host": None, "port": 443,
            "length": None, "format": None, "password": False,
            "firmware_signed": None, "pretty": False,
        }
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(self, k, v)


# ---------------------------------------------------------------------------
# TestVersion
# ---------------------------------------------------------------------------

class TestVersion:
    def test_version_success(self):
        result = cmd_version(_Args())
        assert result["success"] is True
        assert "version" in result
        assert "openssl" in result["version"].lower() or "3." in result["version"]


# ---------------------------------------------------------------------------
# TestHash
# ---------------------------------------------------------------------------

class TestHash:
    def test_hash_text_sha256(self, tmp_path):
        r = cmd_hash(_Args(text="hello world", algorithm="SHA-256"))
        assert r["success"] is True
        assert "command" in r

    def test_hash_file_sha256(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("test content for hashing")
        r = cmd_hash(_Args(file=str(f), algorithm="SHA-256"))
        assert r["success"] is True

    def test_hash_file_sha512(self, tmp_path):
        f = tmp_path / "data.txt"
        f.write_text("test content")
        r = cmd_hash(_Args(file=str(f), algorithm="SHA-512"))
        assert r["success"] is True

    def test_hash_no_input_fails(self):
        r = cmd_hash(_Args())
        assert r["success"] is False
        assert "error" in r

    def test_hash_missing_file_fails(self):
        r = cmd_hash(_Args(file="/nonexistent/file.bin"))
        assert r["success"] is False


# ---------------------------------------------------------------------------
# TestKeygen
# ---------------------------------------------------------------------------

class TestKeygen:
    def test_keygen_ed25519(self, tmp_path):
        out = str(tmp_path / "ed25519.pem")
        r = cmd_keygen(_Args(algorithm="Ed25519", output=out))
        assert r["success"] is True
        assert Path(out).exists()

    def test_keygen_rsa2048(self, tmp_path):
        out = str(tmp_path / "rsa.pem")
        r = cmd_keygen(_Args(algorithm="RSA-2048", output=out))
        assert r["success"] is True
        assert Path(out).exists()

    def test_keygen_ecdsa_p256(self, tmp_path):
        out = str(tmp_path / "ecdsa.pem")
        r = cmd_keygen(_Args(algorithm="ECDSA-P256", output=out))
        assert r["success"] is True
        assert Path(out).exists()

    def test_keygen_no_output_fails(self):
        r = cmd_keygen(_Args(algorithm="Ed25519"))
        assert r["success"] is False
        assert "error" in r

    def test_keygen_result_has_command(self, tmp_path):
        out = str(tmp_path / "key.pem")
        r = cmd_keygen(_Args(algorithm="Ed25519", output=out))
        assert "command" in r
        assert "openssl" in r["command"].lower() or r["command"] == ""


# ---------------------------------------------------------------------------
# TestEncryptDecrypt
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:
    def _make_file(self, tmp_path, content="secret message to encrypt"):
        f = tmp_path / "plain.txt"
        f.write_text(content)
        return str(f)

    def test_encrypt_decrypt_aes256gcm(self, tmp_path):
        plain = self._make_file(tmp_path)
        enc = str(tmp_path / "enc.bin")
        dec = str(tmp_path / "dec.txt")

        r_enc = cmd_encrypt(_Args(file=plain, output=enc, cipher="AES-256-GCM", passphrase="testpass123"))
        assert r_enc["success"] is True, r_enc.get("stderr", "")

        r_dec = cmd_decrypt(_Args(file=enc, output=dec, cipher="AES-256-GCM", passphrase="testpass123"))
        assert r_dec["success"] is True, r_dec.get("stderr", "")
        assert Path(dec).read_text() == "secret message to encrypt"

    def test_encrypt_wrong_passphrase_fails(self, tmp_path):
        plain = self._make_file(tmp_path)
        enc = str(tmp_path / "enc.bin")
        dec = str(tmp_path / "dec.txt")

        cmd_encrypt(_Args(file=plain, output=enc, cipher="AES-256-GCM", passphrase="correct"))
        r = cmd_decrypt(_Args(file=enc, output=dec, cipher="AES-256-GCM", passphrase="wrong"))
        assert r["success"] is False

    def test_encrypt_no_passphrase_fails(self, tmp_path):
        plain = self._make_file(tmp_path)
        r = cmd_encrypt(_Args(file=plain, output=str(tmp_path / "enc.bin"), cipher="AES-256-GCM"))
        assert r["success"] is False

    def test_encrypt_no_file_fails(self):
        r = cmd_encrypt(_Args(passphrase="pass"))
        assert r["success"] is False

    def test_encrypt_chacha20(self, tmp_path):
        plain = self._make_file(tmp_path, "chacha test")
        enc = str(tmp_path / "enc.bin")
        dec = str(tmp_path / "dec.txt")
        r_enc = cmd_encrypt(_Args(file=plain, output=enc, cipher="ChaCha20-Poly1305", passphrase="pw"))
        assert r_enc["success"] is True
        r_dec = cmd_decrypt(_Args(file=enc, output=dec, cipher="ChaCha20-Poly1305", passphrase="pw"))
        assert r_dec["success"] is True


# ---------------------------------------------------------------------------
# TestSignVerify
# ---------------------------------------------------------------------------

class TestSignVerify:
    def _gen_key_and_cert(self, tmp_path) -> tuple[str, str, str]:
        """Generate Ed25519 key + self-signed cert for signing tests."""
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import generate_self_signed_cert

        key = str(tmp_path / "sign_key.pem")
        generate_key("Ed25519", None, key)

        cert = str(tmp_path / "sign_cert.pem")
        generate_self_signed_cert(
            key_path=key, cert_path=cert,
            subject={"CN": "Test Signer", "O": "Test Org", "C": "IN"},
            days=365,
        )
        return key, cert

    def _gen_ecdsa_key(self, tmp_path) -> str:
        from modules.keymgmt.controller import generate_key
        key = str(tmp_path / "ecdsa_key.pem")
        generate_key("ECDSA-P256", None, key)
        return key

    def _make_file(self, tmp_path, name="doc.txt", content="document to sign"):
        f = tmp_path / name
        f.write_text(content)
        return str(f)

    def test_raw_sign_verify_ecdsa(self, tmp_path):
        key = self._gen_ecdsa_key(tmp_path)
        doc = self._make_file(tmp_path)
        sig = str(tmp_path / "doc.sig")

        # Extract public key
        from modules.keymgmt.controller import extract_public_key
        pub = str(tmp_path / "pub.pem")
        extract_public_key(key, pub)

        r_sign = cmd_sign(_Args(file=doc, key=key, output=sig))
        assert r_sign["success"] is True, r_sign.get("stderr", "")

        r_verify = cmd_verify(_Args(file=doc, signature=sig, key=pub))
        assert r_verify["success"] is True, r_verify.get("stderr", "")

    def test_raw_sign_verify_ed25519(self, tmp_path):
        from modules.keymgmt.controller import generate_key, extract_public_key
        key = str(tmp_path / "ed_key.pem")
        generate_key("Ed25519", None, key)
        pub = str(tmp_path / "ed_pub.pem")
        extract_public_key(key, pub)

        doc = self._make_file(tmp_path, "msg.txt", "ed25519 sign test")
        sig = str(tmp_path / "msg.sig")

        r_sign = cmd_sign(_Args(file=doc, key=key, output=sig))
        assert r_sign["success"] is True, r_sign.get("stderr", "")

        r_verify = cmd_verify(_Args(file=doc, signature=sig, key=pub))
        assert r_verify["success"] is True

    def test_verify_tampered_file_fails(self, tmp_path):
        key = self._gen_ecdsa_key(tmp_path)
        from modules.keymgmt.controller import extract_public_key
        pub = str(tmp_path / "pub.pem")
        extract_public_key(key, pub)

        doc = self._make_file(tmp_path)
        sig = str(tmp_path / "doc.sig")

        cmd_sign(_Args(file=doc, key=key, output=sig))

        # Tamper with document
        Path(doc).write_text("tampered content")
        r = cmd_verify(_Args(file=doc, signature=sig, key=pub))
        assert r["success"] is False

    def test_sign_no_key_fails(self):
        r = cmd_sign(_Args(file="/tmp/f", output="/tmp/s"))
        assert r["success"] is False

    def test_sign_no_file_fails(self):
        r = cmd_sign(_Args(key="/tmp/k", output="/tmp/s"))
        assert r["success"] is False


# ---------------------------------------------------------------------------
# TestRandom
# ---------------------------------------------------------------------------

class TestRandom:
    def test_random_bytes_hex(self):
        r = cmd_random(_Args(length=16, format="hex"))
        assert r["success"] is True
        stdout = r.get("stdout", "")
        # hex output: 32 chars for 16 bytes
        assert len(stdout.strip()) == 32

    def test_random_bytes_base64(self):
        r = cmd_random(_Args(length=16, format="base64"))
        assert r["success"] is True

    def test_random_default_hex(self):
        r = cmd_random(_Args())
        assert r["success"] is True

    def test_random_password(self):
        r = cmd_random(_Args(password=True, length=20))
        assert r["success"] is True

    def test_random_different_each_time(self):
        r1 = cmd_random(_Args(length=32, format="hex"))
        r2 = cmd_random(_Args(length=32, format="hex"))
        assert r1["stdout"].strip() != r2["stdout"].strip()


# ---------------------------------------------------------------------------
# TestResultToDict
# ---------------------------------------------------------------------------

class TestResultToDict:
    def test_result_dict_fields(self):
        from core.result import ExecutionResult
        r = ExecutionResult(
            command=["openssl", "version"],
            command_str="openssl version",
            stdout="OpenSSL 3.0.2",
            stderr="",
            parsed={"version": "3.0.2"},
            success=True,
            exit_code=0,
        )
        d = _result_to_dict(r)
        assert d["success"] is True
        assert d["command"] == "openssl version"
        assert d["stdout"] == "OpenSSL 3.0.2"
        assert d["exit_code"] == 0
        assert "deprecated_alg" in d

    def test_result_dict_failure(self):
        from core.result import ExecutionResult
        r = ExecutionResult(
            command=["openssl", "bad"],
            command_str="openssl bad",
            stdout="",
            stderr="error: bad command",
            parsed={},
            success=False,
            exit_code=1,
        )
        d = _result_to_dict(r)
        assert d["success"] is False
        assert d["exit_code"] == 1
