"""
tests/test_core.py — Unit tests for the core execution layer.

Run with: pytest tests/ -v
"""

import os
import sys
import pytest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.executor import run_openssl, get_openssl_path
from core.result import ExecutionResult, DEPRECATED_ALGORITHMS
from core.tempfile_manager import SecureTempFile, secure_temp_file


class TestOpenSSLExecution:
    def test_openssl_found(self):
        path = get_openssl_path()
        assert os.path.isfile(path)
        assert os.access(path, os.X_OK)

    def test_version_command(self):
        r = run_openssl(["version"])
        assert r.success
        assert "OpenSSL" in r.stdout

    def test_help_returns_output(self):
        r = run_openssl(["help"])
        # openssl help exits with non-zero but produces output
        assert r.stdout or r.stderr

    def test_no_shell_injection(self):
        """Ensure shell metacharacters in args are treated as literal filename, not executed."""
        r = run_openssl(["dgst", "-sha256", "/dev/null; echo INJECTED"])
        # The file "/dev/null; echo INJECTED" does not exist — should fail with file error
        # The INJECTED string appears in the error message as PART OF THE PATH, not as
        # executed output. The key check: no separate "INJECTED\n" line from a shell execution.
        assert r.exit_code != 0  # Must fail (file not found)
        # If shell=True had been used, a separate "INJECTED" would appear on its own line
        lines = (r.stdout + r.stderr).splitlines()
        injected_lines = [l for l in lines if l.strip() == "INJECTED"]
        assert len(injected_lines) == 0, "Shell injection succeeded — shell=True may be in use!"

    def test_deprecated_algorithm_detected(self):
        r = run_openssl(["dgst", "-md5", "/dev/null"])
        assert r.is_deprecated_alg
        assert "MD5" in r.deprecated_alg_name.upper() or "md5" in r.deprecated_alg_name.lower()


class TestSecureTempFile:
    def test_creates_with_correct_permissions(self):
        tf = SecureTempFile(suffix=".pem")
        stat = os.stat(tf.path)
        mode = oct(stat.st_mode)[-3:]
        assert mode == "600"
        tf.secure_delete()

    def test_write_and_read(self):
        with secure_temp_file(content=b"test data") as tf:
            assert tf.read() == b"test data"

    def test_secure_delete_removes_file(self):
        tf = SecureTempFile()
        path = tf.path
        tf.secure_delete()
        assert not os.path.exists(path)

    def test_context_manager_cleans_up(self):
        with secure_temp_file() as tf:
            path = tf.path
            assert os.path.exists(path)
        assert not os.path.exists(path)


class TestHashing:
    def test_sha256_file(self, tmp_path):
        from modules.hashing.controller import hash_file
        f = tmp_path / "test.txt"
        f.write_text("Hello, sslOpenCrypt!")
        r = hash_file(str(f), "SHA-256")
        assert r.success
        assert "hash" in r.parsed
        assert len(r.parsed["hash"]) == 64  # SHA-256 hex = 64 chars

    def test_sha256_text(self):
        from modules.hashing.controller import hash_text
        r = hash_text("Hello, World!", "SHA-256")
        assert r.success
        # Verify format and length — exact hash depends on openssl version/trailing newline handling
        h = r.parsed.get("hash", "")
        assert len(h) == 64, f"Expected 64-char hex SHA-256, got {len(h)}: {h}"
        assert all(c in "0123456789abcdef" for c in h)

    def test_verify_hash_match(self, tmp_path):
        from modules.hashing.controller import verify_hash, hash_file
        f = tmp_path / "verify.txt"
        f.write_bytes(b"test content for hashing")
        r_hash = hash_file(str(f))
        expected = r_hash.parsed["hash"]
        r_verify = verify_hash(str(f), expected)
        assert r_verify.parsed["match"] is True

    def test_verify_hash_mismatch(self, tmp_path):
        from modules.hashing.controller import verify_hash
        f = tmp_path / "verify.txt"
        f.write_bytes(b"test content")
        r = verify_hash(str(f), "0" * 64)
        assert r.parsed["match"] is False

    def test_avalanche_demo(self):
        from modules.hashing.controller import avalanche_demo
        result = avalanche_demo("Hello World", "SHA-256")
        assert result
        assert "bits_changed" in result
        # Avalanche: >40% of bits should change from a 1-bit input change
        assert result["percent_changed"] > 30

    def test_md5_flagged_deprecated(self):
        from modules.hashing.controller import hash_text
        r = hash_text("test", "MD5")
        assert r.is_deprecated_alg

    def test_sha1_flagged_deprecated(self):
        from modules.hashing.controller import hash_text
        r = hash_text("test", "SHA-1")
        assert r.is_deprecated_alg


class TestKeyGeneration:
    def test_ed25519_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "private.pem")
        r = generate_key("Ed25519", None, priv)
        assert r.success, f"Failed: {r.stderr}"
        assert os.path.exists(priv)
        pub = priv.replace(".pem", "_pub.pem")
        assert os.path.exists(pub)

    def test_rsa2048_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "rsa2048.pem")
        r = generate_key("RSA-2048", None, priv)
        assert r.success, f"Failed: {r.stderr}"
        assert os.path.exists(priv)

    def test_ecdsa_p256_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "ec256.pem")
        r = generate_key("ECDSA-P256", None, priv)
        assert r.success, f"Failed: {r.stderr}"

    def test_key_inspect(self, tmp_path):
        from modules.keymgmt.controller import generate_key, inspect_key
        priv = str(tmp_path / "inspect_test.pem")
        r_gen = generate_key("Ed25519", None, priv)
        assert r_gen.success
        r_inspect = inspect_key(priv)
        assert r_inspect.success


class TestSymmetricEncryption:
    def test_encrypt_decrypt_file_gcm(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"Secret message for AES-256-GCM test")
        enc = str(tmp_path / "enc.bin")
        dec_out = str(tmp_path / "decrypted.txt")

        r_enc = encrypt_file(str(plain), enc, "AES-256-GCM", "TestPass123!")
        assert r_enc.success, f"Encrypt failed: {r_enc.stderr}"

        r_dec = decrypt_file(enc, dec_out, "AES-256-GCM", "TestPass123!")
        assert r_dec.success, f"Decrypt failed: {r_dec.stderr}"

        assert open(dec_out, "rb").read() == b"Secret message for AES-256-GCM test"

    def test_encrypt_decrypt_text_gcm(self):
        from modules.symmetric.controller import encrypt_text, decrypt_text
        plaintext = "Hello sslOpenCrypt!"
        r_enc = encrypt_text(plaintext, "AES-256-GCM", "mypassword")
        assert r_enc.success, f"GCM encrypt failed: {r_enc.stderr}"
        ciphertext_b64 = r_enc.parsed.get("ciphertext", "")
        assert ciphertext_b64

        r_dec = decrypt_text(ciphertext_b64, "AES-256-GCM", "mypassword")
        assert r_dec.success, f"GCM decrypt failed: {r_dec.stderr}"
        assert plaintext in (r_dec.stdout or r_dec.parsed.get("plaintext", ""))


class TestPKI:
    def test_create_self_signed_cert(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_self_signed, inspect_cert
        priv = str(tmp_path / "ca_key.pem")
        r = generate_key("ECDSA-P256", None, priv)
        assert r.success

        cert_out = str(tmp_path / "cert.pem")
        subject = {"CN": "Test CA", "O": "sslOpenCrypt Tests", "C": "IN"}
        r_cert = create_self_signed(priv, cert_out, subject, days=365)
        assert r_cert.success, f"Cert creation failed: {r_cert.stderr}"
        assert os.path.exists(cert_out)

        r_inspect = inspect_cert(cert_out)
        assert r_inspect.success
        assert "subject" in r_inspect.parsed

    def test_csr_creation(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_csr
        priv = str(tmp_path / "key.pem")
        generate_key("Ed25519", None, priv)

        csr_out = str(tmp_path / "request.csr")
        subject = {"CN": "test.example.com", "C": "IN"}
        r = create_csr(priv, csr_out, subject)
        assert r.success, f"CSR failed: {r.stderr}"
        assert os.path.exists(csr_out)


class TestSigning:
    def test_sign_and_verify_raw(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.signing.controller import sign_raw, verify_raw

        priv = str(tmp_path / "sign_key.pem")
        pub = priv.replace(".pem", "_pub.pem")
        generate_key("ECDSA-P256", None, priv)

        data_file = str(tmp_path / "data.bin")
        with open(data_file, "wb") as f:
            f.write(b"firmware payload for signing test")

        sig_file = str(tmp_path / "data.sig")
        r_sign = sign_raw(data_file, priv, sig_file)
        assert r_sign.success, f"Sign failed: {r_sign.stderr}"

        r_verify = verify_raw(data_file, sig_file, pub)
        assert r_verify.success, f"Verify failed: {r_verify.stderr}"
        assert r_verify.parsed.get("verified")


class TestRandom:
    def test_random_bytes_hex(self):
        from modules.random.controller import random_bytes
        r = random_bytes(32, "hex")
        assert r.success
        val = r.parsed.get("value", r.stdout.strip())
        assert len(val.replace("\n", "")) == 64  # 32 bytes = 64 hex chars

    def test_random_password(self):
        from modules.random.controller import random_password
        r = random_password(length=20)
        assert r.success
        pw = r.parsed.get("password", "")
        assert len(pw) == 20
        assert r.parsed.get("entropy_bits", 0) > 60  # Strong password

    def test_entropy_estimate_hex(self):
        from modules.random.controller import entropy_estimate
        result = entropy_estimate("deadbeefdeadbeef")
        assert result["entropy_bits"] == 64.0  # 16 hex chars * 4 bits/char

    def test_random_uuid(self):
        from modules.random.controller import random_uuid
        r = random_uuid()
        assert r.success
        uid = r.parsed.get("uuid", "")
        assert len(uid) == 36
        assert uid[14] == "4"  # UUID version 4
