"""
tests/test_comprehensive.py — Comprehensive test suite for sslOpenCrypt.

Covers all modules with positive and negative paths:
  - core: result, audit_log, executor edge cases
  - keymgmt: all key types, passphrase, conversion, extract_public
  - symmetric: all cipher modes, wrong passphrase, deprecated flags
  - hashing: all algorithms, HMAC, batch_hash
  - pki: CA workflow, PKCS12 round-trip, cert chain verification
  - signing: CMS sign/verify, batch sign
  - smime: sign/verify, encrypt/decrypt
  - tls: build_config, rate_config (no network)
  - random: prime, base64, entropy estimates
  - gpg: list_keys (graceful if unavailable)
  - audit_log: read/export

Run with: pytest tests/ -v
"""

import json
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.executor import run_openssl, run_gpg, get_openssl_path, get_gpg_path, openssl_version
from core.result import ExecutionResult, DEPRECATED_ALGORITHMS
from core.tempfile_manager import SecureTempFile, secure_temp_file
from core.audit_log import log_operation, read_log, export_log


# ---------------------------------------------------------------------------
# Core: ExecutionResult properties
# ---------------------------------------------------------------------------

class TestExecutionResult:
    def test_output_property_stdout_only(self):
        r = ExecutionResult([], "", "hello", "", {}, True, 0)
        assert r.output == "hello"

    def test_output_property_both(self):
        r = ExecutionResult([], "", "out", "err", {}, False, 1)
        assert "out" in r.output
        assert "err" in r.output

    def test_output_property_empty(self):
        r = ExecutionResult([], "", "", "", {}, True, 0)
        assert r.output == ""

    def test_error_message_on_success(self):
        r = ExecutionResult([], "", "ok", "", {}, True, 0)
        assert r.error_message == ""

    def test_error_message_on_failure(self):
        r = ExecutionResult([], "", "", "something went wrong", {}, False, 1)
        assert r.error_message == "something went wrong"

    def test_error_message_fallback_to_exit_code(self):
        r = ExecutionResult([], "", "", "", {}, False, 42)
        assert "42" in r.error_message

    def test_deprecated_defaults(self):
        r = ExecutionResult([], "", "", "", {}, True, 0)
        assert r.is_deprecated_alg is False
        assert r.deprecated_alg_name == ""

    def test_deprecated_algorithms_dict_populated(self):
        assert "md5" in DEPRECATED_ALGORITHMS
        assert "sha1" in DEPRECATED_ALGORITHMS
        assert "3des" in DEPRECATED_ALGORITHMS
        assert "rc4" in DEPRECATED_ALGORITHMS


# ---------------------------------------------------------------------------
# Core: Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_log_operation_creates_entry(self):
        before = len(read_log(max_entries=100_000))
        log_operation("test_module", "test_op", "openssl test", True)
        after = len(read_log(max_entries=100_000))
        assert after == before + 1

    def test_log_entry_fields(self):
        log_operation("keymgmt", "test_keymgmt_op", "openssl genpkey ...", True)
        entries = read_log()
        last = entries[-1]
        assert last["module"] == "keymgmt"
        assert last["operation"] == "test_keymgmt_op"
        assert last["success"] is True
        assert "ts" in last

    def test_log_deprecated_flag(self):
        log_operation("hashing", "hash_md5", "openssl dgst -md5", False,
                      is_deprecated=True, deprecated_alg="MD5")
        entries = read_log()
        last = entries[-1]
        assert last.get("flag") == "DEPRECATED_ALG"
        assert last.get("alg") == "MD5"

    def test_export_log(self, tmp_path):
        log_operation("test", "export_test", "cmd", True)
        out_file = str(tmp_path / "audit_export.json")
        export_log(out_file)
        assert os.path.exists(out_file)
        with open(out_file) as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_read_log_max_entries(self):
        # Write a few entries, verify max_entries truncates
        for i in range(5):
            log_operation("test", f"op_{i}", "cmd", True)
        entries = read_log(max_entries=3)
        assert len(entries) <= 3


# ---------------------------------------------------------------------------
# Core: executor edge cases
# ---------------------------------------------------------------------------

class TestExecutorEdgeCases:
    def test_openssl_version_returns_string(self):
        ver = openssl_version()
        assert "OpenSSL" in ver

    def test_run_openssl_timeout_parameter(self):
        """Short commands complete well within timeout — just verifying param is accepted."""
        r = run_openssl(["version"], timeout=30)
        assert r.success

    def test_run_openssl_input_data(self):
        """Pipe data into openssl dgst via stdin."""
        r = run_openssl(["dgst", "-sha256"], input_data=b"test input")
        assert r.success
        assert len(r.stdout.strip().split("= ")[-1]) == 64

    def test_run_gpg_returns_result_even_without_gpg(self):
        """run_gpg must always return ExecutionResult, even if gpg is missing."""
        r = run_gpg(["--version"])
        assert isinstance(r, ExecutionResult)
        # Either success (gpg installed) or failure with helpful error
        if not r.success:
            assert "gpg" in r.stderr.lower() or "not found" in r.stderr.lower()

    def test_gpg_path_returns_none_or_string(self):
        path = get_gpg_path()
        assert path is None or (isinstance(path, str) and os.path.isfile(path))


# ---------------------------------------------------------------------------
# Hashing: extended algorithms, HMAC, batch
# ---------------------------------------------------------------------------

class TestHashingExtended:
    def test_sha512_file(self, tmp_path):
        from modules.hashing.controller import hash_file
        f = tmp_path / "f.bin"
        f.write_bytes(b"sha512 test data")
        r = hash_file(str(f), "SHA-512")
        assert r.success
        h = r.parsed.get("hash", "")
        assert len(h) == 128  # SHA-512 = 128 hex chars

    def test_sha3_256_text(self):
        from modules.hashing.controller import hash_text
        r = hash_text("SHA-3 test", "SHA3-256")
        assert r.success
        h = r.parsed.get("hash", "")
        assert len(h) == 64

    def test_blake2b512_text(self):
        from modules.hashing.controller import hash_text
        r = hash_text("BLAKE2 test", "BLAKE2b512")
        assert r.success
        h = r.parsed.get("hash", "")
        assert len(h) == 128  # BLAKE2b-512 = 128 hex chars

    def test_hmac_file_sha256(self, tmp_path):
        from modules.hashing.controller import hmac_file
        f = tmp_path / "data.txt"
        f.write_bytes(b"data to HMAC")
        r = hmac_file(str(f), "secret_key", "SHA-256")
        assert r.success
        h = r.parsed.get("hmac", "")
        assert len(h) == 64
        assert r.parsed.get("algorithm") == "HMAC-SHA-256"

    def test_hmac_text_sha256(self):
        from modules.hashing.controller import hmac_text
        r = hmac_text("hello", "mykey", "SHA-256")
        assert r.success
        h = r.parsed.get("hmac", "")
        assert len(h) == 64

    def test_hmac_different_keys_produce_different_results(self):
        from modules.hashing.controller import hmac_text
        r1 = hmac_text("same text", "key1")
        r2 = hmac_text("same text", "key2")
        assert r1.success and r2.success
        assert r1.parsed["hmac"] != r2.parsed["hmac"]

    def test_hash_empty_string(self):
        from modules.hashing.controller import hash_text
        r = hash_text("", "SHA-256")
        assert r.success
        h = r.parsed.get("hash", "")
        # SHA-256 of empty string is well-known
        assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_batch_hash_directory(self, tmp_path):
        from modules.hashing.controller import batch_hash
        (tmp_path / "a.txt").write_bytes(b"file a")
        (tmp_path / "b.txt").write_bytes(b"file b")
        (tmp_path / "c.txt").write_bytes(b"file c")
        results = batch_hash(str(tmp_path), "SHA-256")
        assert len(results) == 3
        for item in results:
            assert item["success"]
            assert len(item["hash"]) == 64

    def test_batch_hash_recursive(self, tmp_path):
        from modules.hashing.controller import batch_hash
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "top.txt").write_bytes(b"top")
        (sub / "nested.txt").write_bytes(b"nested")
        results = batch_hash(str(tmp_path), "SHA-256", recursive=True)
        files = [r["file"] for r in results]
        assert any("nested.txt" in f for f in files)
        assert any("top.txt" in f for f in files)

    def test_hash_deterministic(self):
        from modules.hashing.controller import hash_text
        r1 = hash_text("deterministic input", "SHA-256")
        r2 = hash_text("deterministic input", "SHA-256")
        assert r1.parsed["hash"] == r2.parsed["hash"]

    def test_avalanche_sha512(self):
        from modules.hashing.controller import avalanche_demo
        result = avalanche_demo("Test avalanche SHA512", "SHA-512")
        assert result
        assert result["percent_changed"] > 30
        assert result["total_bits"] == 512


# ---------------------------------------------------------------------------
# Key Management: extended
# ---------------------------------------------------------------------------

class TestKeyManagementExtended:
    def test_rsa4096_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "rsa4096.pem")
        r = generate_key("RSA-4096", None, priv)
        assert r.success, f"RSA-4096 failed: {r.stderr}"
        assert os.path.exists(priv)

    def test_ed448_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "ed448.pem")
        r = generate_key("Ed448", None, priv)
        assert r.success, f"Ed448 failed: {r.stderr}"
        assert os.path.exists(priv)

    def test_x25519_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "x25519.pem")
        r = generate_key("X25519", None, priv)
        assert r.success, f"X25519 failed: {r.stderr}"

    def test_ecdsa_p384_keygen(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "ec384.pem")
        r = generate_key("ECDSA-P384", None, priv)
        assert r.success, f"ECDSA-P384 failed: {r.stderr}"

    def test_passphrase_protected_rsa_key(self, tmp_path):
        from modules.keymgmt.controller import generate_key, inspect_key
        priv = str(tmp_path / "rsa_enc.pem")
        r = generate_key("RSA-2048", "test_passphrase_123", priv)
        assert r.success, f"Encrypted RSA keygen failed: {r.stderr}"
        # Inspect requires passphrase
        r_inspect = inspect_key(priv, passphrase="test_passphrase_123")
        assert r_inspect.success

    def test_inspect_key_without_passphrase_fails_for_encrypted(self, tmp_path):
        from modules.keymgmt.controller import generate_key, inspect_key
        priv = str(tmp_path / "rsa_enc2.pem")
        r = generate_key("RSA-2048", "secret_pass", priv)
        assert r.success
        r_inspect = inspect_key(priv)  # no passphrase
        assert not r_inspect.success

    def test_extract_public_key(self, tmp_path):
        from modules.keymgmt.controller import generate_key, extract_public_key
        priv = str(tmp_path / "priv.pem")
        generate_key("ECDSA-P256", None, priv)
        pub_out = str(tmp_path / "pub_extracted.pem")
        r = extract_public_key(priv, pub_out)
        assert r.success, f"extract_public_key failed: {r.stderr}"
        assert os.path.exists(pub_out)
        with open(pub_out) as f:
            content = f.read()
        assert "PUBLIC KEY" in content

    def test_convert_key_pem_to_der(self, tmp_path):
        from modules.keymgmt.controller import generate_key, convert_key
        priv = str(tmp_path / "priv.pem")
        generate_key("RSA-2048", None, priv)
        der_out = str(tmp_path / "priv.der")
        r = convert_key(priv, der_out, "PEM", "DER")
        assert r.success, f"PEM→DER conversion failed: {r.stderr}"
        assert os.path.exists(der_out)
        # DER files are binary — should not start with "-----BEGIN"
        with open(der_out, "rb") as f:
            data = f.read(10)
        assert not data.startswith(b"-----BEGIN")

    def test_convert_key_der_back_to_pem(self, tmp_path):
        from modules.keymgmt.controller import generate_key, convert_key
        priv = str(tmp_path / "priv.pem")
        generate_key("RSA-2048", None, priv)
        der_out = str(tmp_path / "priv.der")
        convert_key(priv, der_out, "PEM", "DER")
        pem_out = str(tmp_path / "priv_back.pem")
        r = convert_key(der_out, pem_out, "DER", "PEM")
        assert r.success, f"DER→PEM conversion failed: {r.stderr}"
        with open(pem_out) as f:
            content = f.read()
        assert "PRIVATE KEY" in content

    def test_rsa_key_inspect_shows_type(self, tmp_path):
        from modules.keymgmt.controller import generate_key, inspect_key
        priv = str(tmp_path / "rsa.pem")
        generate_key("RSA-2048", None, priv)
        r = inspect_key(priv)
        assert r.success
        assert r.parsed.get("key_type") == "RSA"
        assert r.parsed.get("key_bits") == 2048

    def test_ed25519_key_inspect_shows_type(self, tmp_path):
        from modules.keymgmt.controller import generate_key, inspect_key
        priv = str(tmp_path / "ed25519.pem")
        generate_key("Ed25519", None, priv)
        r = inspect_key(priv)
        assert r.success
        assert r.parsed.get("key_type") == "Ed25519"

    def test_generate_key_command_str_logged(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "log_test.pem")
        r = generate_key("Ed25519", None, priv)
        assert r.success
        assert r.command_str  # should have a non-empty command string


# ---------------------------------------------------------------------------
# Symmetric: extended ciphers, wrong passphrase, deprecated
# ---------------------------------------------------------------------------

class TestSymmetricExtended:
    def test_encrypt_decrypt_file_cbc(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"AES-256-CBC test data")
        enc = str(tmp_path / "enc.bin")
        dec_out = str(tmp_path / "dec.txt")
        r_enc = encrypt_file(str(plain), enc, "AES-256-CBC", "passw0rd!")
        assert r_enc.success, f"CBC encrypt failed: {r_enc.stderr}"
        assert "cbc_warning" in r_enc.parsed  # integrity warning present
        r_dec = decrypt_file(enc, dec_out, "AES-256-CBC", "passw0rd!")
        assert r_dec.success, f"CBC decrypt failed: {r_dec.stderr}"
        assert open(dec_out, "rb").read() == b"AES-256-CBC test data"

    def test_encrypt_decrypt_file_ctr(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"AES-256-CTR test data")
        enc = str(tmp_path / "enc_ctr.bin")
        dec_out = str(tmp_path / "dec_ctr.txt")
        r_enc = encrypt_file(str(plain), enc, "AES-256-CTR", "ctr_pass")
        assert r_enc.success, f"CTR encrypt failed: {r_enc.stderr}"
        r_dec = decrypt_file(enc, dec_out, "AES-256-CTR", "ctr_pass")
        assert r_dec.success, f"CTR decrypt failed: {r_dec.stderr}"
        assert open(dec_out, "rb").read() == b"AES-256-CTR test data"

    def test_encrypt_decrypt_file_chacha20(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"ChaCha20-Poly1305 file test")
        enc = str(tmp_path / "enc_cc.bin")
        dec_out = str(tmp_path / "dec_cc.txt")
        r_enc = encrypt_file(str(plain), enc, "ChaCha20-Poly1305", "cc_pass")
        assert r_enc.success, f"ChaCha20 encrypt failed: {r_enc.stderr}"
        r_dec = decrypt_file(enc, dec_out, "ChaCha20-Poly1305", "cc_pass")
        assert r_dec.success, f"ChaCha20 decrypt failed: {r_dec.stderr}"
        assert open(dec_out, "rb").read() == b"ChaCha20-Poly1305 file test"

    def test_encrypt_decrypt_text_cbc(self):
        from modules.symmetric.controller import encrypt_text, decrypt_text
        plaintext = "CBC text encryption test"
        r_enc = encrypt_text(plaintext, "AES-256-CBC", "cbc_password")
        assert r_enc.success
        ct = r_enc.parsed.get("ciphertext", "")
        assert ct
        r_dec = decrypt_text(ct, "AES-256-CBC", "cbc_password")
        assert r_dec.success, f"CBC text decrypt failed: {r_dec.stderr}"
        assert plaintext in (r_dec.stdout or r_dec.parsed.get("plaintext", ""))

    def test_encrypt_decrypt_text_chacha20(self):
        from modules.symmetric.controller import encrypt_text, decrypt_text
        plaintext = "ChaCha20 text test"
        r_enc = encrypt_text(plaintext, "ChaCha20-Poly1305", "cc_text_pass")
        assert r_enc.success
        ct = r_enc.parsed.get("ciphertext", "")
        r_dec = decrypt_text(ct, "ChaCha20-Poly1305", "cc_text_pass")
        assert r_dec.success
        assert plaintext in (r_dec.stdout or r_dec.parsed.get("plaintext", ""))

    def test_gcm_wrong_passphrase_fails(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"secret data")
        enc = str(tmp_path / "enc.bin")
        dec_out = str(tmp_path / "dec.txt")
        r_enc = encrypt_file(str(plain), enc, "AES-256-GCM", "right_pass")
        assert r_enc.success
        r_dec = decrypt_file(enc, dec_out, "AES-256-GCM", "wrong_pass")
        assert not r_dec.success, "GCM decryption with wrong passphrase should fail"

    def test_cbc_wrong_passphrase_fails(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"cbc test data")
        enc = str(tmp_path / "enc.bin")
        dec_out = str(tmp_path / "dec.txt")
        r_enc = encrypt_file(str(plain), enc, "AES-256-CBC", "right_pass")
        assert r_enc.success
        r_dec = decrypt_file(enc, dec_out, "AES-256-CBC", "wrong_pass")
        assert not r_dec.success, "CBC decryption with wrong passphrase should fail"

    def test_3des_deprecated_encrypt_flag(self, tmp_path):
        from modules.symmetric.controller import encrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"3DES legacy test")
        enc = str(tmp_path / "enc3des.bin")
        r = encrypt_file(str(plain), enc, "3DES-CBC", "pass123")
        assert r.success, f"3DES-CBC encrypt failed: {r.stderr}"
        assert r.is_deprecated_alg, "3DES-CBC must be flagged as deprecated"
        assert "3DES" in r.deprecated_alg_name.upper() or "3des" in r.deprecated_alg_name.lower()

    def test_3des_decrypt_deprecated_flag(self, tmp_path):
        """decrypt_file should also flag 3DES-CBC as deprecated."""
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"3DES legacy test")
        enc = str(tmp_path / "enc3des.bin")
        dec_out = str(tmp_path / "dec3des.txt")
        encrypt_file(str(plain), enc, "3DES-CBC", "pass123")
        r_dec = decrypt_file(enc, dec_out, "3DES-CBC", "pass123")
        assert r_dec.success, f"3DES-CBC decrypt failed: {r_dec.stderr}"
        assert r_dec.is_deprecated_alg, "3DES-CBC decrypt should also be flagged as deprecated"

    def test_encrypt_unknown_cipher_returns_failure(self, tmp_path):
        from modules.symmetric.controller import encrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"test")
        r = encrypt_file(str(plain), str(tmp_path / "out.bin"), "NON-EXISTENT-CIPHER", "pass")
        assert not r.success

    def test_ciphertext_differs_each_call_gcm(self):
        """GCM uses random nonce — same plaintext+passphrase produces different ciphertext."""
        from modules.symmetric.controller import encrypt_text
        r1 = encrypt_text("same plaintext", "AES-256-GCM", "same_pass")
        r2 = encrypt_text("same plaintext", "AES-256-GCM", "same_pass")
        assert r1.success and r2.success
        assert r1.parsed["ciphertext"] != r2.parsed["ciphertext"]

    def test_aes_128_gcm_encrypt_decrypt(self, tmp_path):
        from modules.symmetric.controller import encrypt_file, decrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"AES-128-GCM test")
        enc = str(tmp_path / "enc128.bin")
        dec = str(tmp_path / "dec128.txt")
        r_enc = encrypt_file(str(plain), enc, "AES-128-GCM", "pass128")
        assert r_enc.success
        r_dec = decrypt_file(enc, dec, "AES-128-GCM", "pass128")
        assert r_dec.success
        assert open(dec, "rb").read() == b"AES-128-GCM test"

    def test_list_supported_ciphers(self):
        from modules.symmetric.controller import list_supported_ciphers
        r = list_supported_ciphers()
        assert r.stdout or r.stderr  # returns some output


# ---------------------------------------------------------------------------
# PKI: full CA workflow, PKCS12, verify chain
# ---------------------------------------------------------------------------

class TestPKIExtended:
    @pytest.fixture
    def ca_setup(self, tmp_path):
        """Create a CA key, CA cert, end-entity key, CSR, and signed cert."""
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_root_ca, create_csr, sign_csr

        ca_key = str(tmp_path / "ca_key.pem")
        ca_cert = str(tmp_path / "ca_cert.pem")
        ee_key = str(tmp_path / "ee_key.pem")
        ee_csr = str(tmp_path / "ee.csr")
        ee_cert = str(tmp_path / "ee_cert.pem")

        generate_key("RSA-2048", None, ca_key)
        r_ca = create_root_ca(ca_key, ca_cert, {"CN": "Test Root CA", "C": "IN"}, days=3650)
        assert r_ca.success, f"CA creation failed: {r_ca.stderr}"

        generate_key("RSA-2048", None, ee_key)
        r_csr = create_csr(ee_key, ee_csr, {"CN": "test.example.com", "C": "IN"})
        assert r_csr.success, f"CSR creation failed: {r_csr.stderr}"

        r_sign = sign_csr(ca_cert, ca_key, ee_csr, ee_cert, days=365)
        assert r_sign.success, f"CSR signing failed: {r_sign.stderr}"

        return {
            "ca_key": ca_key, "ca_cert": ca_cert,
            "ee_key": ee_key, "ee_csr": ee_csr, "ee_cert": ee_cert,
            "tmp_path": tmp_path,
        }

    def test_create_root_ca(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_root_ca, inspect_cert
        priv = str(tmp_path / "root_key.pem")
        generate_key("ECDSA-P256", None, priv)
        cert = str(tmp_path / "root_ca.pem")
        r = create_root_ca(priv, cert, {"CN": "Root CA", "O": "Test Org", "C": "IN"}, days=3650)
        assert r.success, f"create_root_ca failed: {r.stderr}"
        r_inspect = inspect_cert(cert)
        assert r_inspect.success
        assert "subject" in r_inspect.parsed

    def test_sign_csr_full_workflow(self, ca_setup):
        from modules.pki.controller import inspect_cert
        # ee_cert should exist and be verifiable
        r = inspect_cert(ca_setup["ee_cert"])
        assert r.success
        assert "test.example.com" in r.parsed.get("subject", "")

    def test_verify_cert_chain(self, ca_setup):
        from modules.pki.controller import verify_cert_chain
        r = verify_cert_chain(ca_setup["ee_cert"], ca_setup["ca_cert"])
        assert r.success, f"Cert chain verification failed: {r.stderr}"
        assert r.parsed.get("verified") is True

    def test_verify_cert_chain_with_wrong_ca_fails(self, tmp_path, ca_setup):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_self_signed, verify_cert_chain
        # Create an unrelated CA
        unrelated_key = str(tmp_path / "unrelated_key.pem")
        generate_key("RSA-2048", None, unrelated_key)
        unrelated_cert = str(tmp_path / "unrelated_ca.pem")
        create_self_signed(unrelated_key, unrelated_cert, {"CN": "Unrelated CA", "C": "IN"})
        r = verify_cert_chain(ca_setup["ee_cert"], unrelated_cert)
        assert not r.success

    def test_inspect_cert_fields(self, ca_setup):
        from modules.pki.controller import inspect_cert
        r = inspect_cert(ca_setup["ee_cert"])
        assert r.success
        parsed = r.parsed
        assert "subject" in parsed
        assert "issuer" in parsed
        assert "not_before" in parsed
        assert "not_after" in parsed
        assert "sig_algorithm" in parsed

    def test_create_pkcs12_and_import(self, ca_setup):
        from modules.pki.controller import create_pkcs12, import_pkcs12
        pfx_path = str(ca_setup["tmp_path"] / "bundle.p12")
        r_create = create_pkcs12(
            ca_setup["ee_cert"], ca_setup["ee_key"], pfx_path,
            password="p12_pass", friendly_name="test-bundle"
        )
        assert r_create.success, f"PKCS12 creation failed: {r_create.stderr}"
        assert os.path.exists(pfx_path)

        cert_out = str(ca_setup["tmp_path"] / "imported_cert.pem")
        key_out = str(ca_setup["tmp_path"] / "imported_key.pem")
        r_import = import_pkcs12(pfx_path, "p12_pass", cert_out, key_out)
        assert r_import.success, f"PKCS12 import failed: {r_import.stderr}"
        assert os.path.exists(cert_out)
        assert os.path.exists(key_out)

    def test_csr_with_san(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_csr
        priv = str(tmp_path / "san_key.pem")
        generate_key("ECDSA-P256", None, priv)
        csr_out = str(tmp_path / "san.csr")
        r = create_csr(
            priv, csr_out,
            subject={"CN": "multi.example.com", "C": "IN"},
            san_list=["DNS:multi.example.com", "DNS:www.multi.example.com", "IP:192.168.1.1"]
        )
        assert r.success, f"CSR with SAN failed: {r.stderr}"

    def test_self_signed_with_san(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_self_signed, inspect_cert
        priv = str(tmp_path / "san_ss_key.pem")
        generate_key("ECDSA-P256", None, priv)
        cert_out = str(tmp_path / "san_ss.pem")
        r = create_self_signed(
            priv, cert_out,
            subject={"CN": "san.example.com", "C": "IN"},
            days=365,
            san_list=["DNS:san.example.com", "DNS:www.san.example.com"]
        )
        assert r.success, f"Self-signed with SAN failed: {r.stderr}"
        r_inspect = inspect_cert(cert_out)
        assert r_inspect.success
        san = r_inspect.parsed.get("san", [])
        assert any("san.example.com" in s for s in san)


# ---------------------------------------------------------------------------
# Signing: CMS sign/verify, batch
# ---------------------------------------------------------------------------

class TestSigningExtended:
    @pytest.fixture
    def signing_setup(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_self_signed
        priv = str(tmp_path / "sign_key.pem")
        generate_key("ECDSA-P256", None, priv)
        cert = str(tmp_path / "sign_cert.pem")
        create_self_signed(priv, cert, {"CN": "Signer", "C": "IN"}, days=365)
        return {"priv": priv, "cert": cert, "tmp_path": tmp_path}

    def test_cms_sign_and_verify(self, signing_setup):
        from modules.signing.controller import sign_file, verify_file
        data_file = str(signing_setup["tmp_path"] / "document.txt")
        with open(data_file, "w") as f:
            f.write("Document content for CMS signing test")
        sig_file = str(signing_setup["tmp_path"] / "document.p7s")

        r_sign = sign_file(data_file, signing_setup["priv"], signing_setup["cert"], sig_file)
        assert r_sign.success, f"CMS sign failed: {r_sign.stderr}"
        assert os.path.exists(sig_file)

        r_verify = verify_file(data_file, sig_file, no_verify_cert=True)
        assert r_verify.success, f"CMS verify failed: {r_verify.stderr}"
        assert r_verify.parsed.get("verified") is True

    def test_cms_verify_fails_on_tampered_content(self, signing_setup):
        from modules.signing.controller import sign_file, verify_file
        data_file = str(signing_setup["tmp_path"] / "original.txt")
        with open(data_file, "w") as f:
            f.write("Original content")
        sig_file = str(signing_setup["tmp_path"] / "sig.p7s")
        sign_file(data_file, signing_setup["priv"], signing_setup["cert"], sig_file)

        # Tampered file
        tampered = str(signing_setup["tmp_path"] / "tampered.txt")
        with open(tampered, "w") as f:
            f.write("Tampered content — different from what was signed")

        r_verify = verify_file(tampered, sig_file, no_verify_cert=True)
        assert not r_verify.success, "Verification of tampered content should fail"

    def test_raw_sign_verify_ed25519(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.signing.controller import sign_raw, verify_raw
        priv = str(tmp_path / "ed_key.pem")
        pub = priv.replace(".pem", "_pub.pem")
        generate_key("Ed25519", None, priv)
        data_file = str(tmp_path / "data.bin")
        with open(data_file, "wb") as f:
            f.write(b"Ed25519 signing test data")
        sig_file = str(tmp_path / "data.sig")
        r_sign = sign_raw(data_file, priv, sig_file)
        assert r_sign.success, f"Ed25519 raw sign failed: {r_sign.stderr}"
        r_verify = verify_raw(data_file, sig_file, pub)
        assert r_verify.success, f"Ed25519 raw verify failed: {r_verify.stderr}"
        assert r_verify.parsed.get("verified")

    def test_raw_sign_verify_rsa(self, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.signing.controller import sign_raw, verify_raw
        priv = str(tmp_path / "rsa_sign.pem")
        pub = priv.replace(".pem", "_pub.pem")
        generate_key("RSA-2048", None, priv)
        data_file = str(tmp_path / "data.txt")
        with open(data_file, "w") as f:
            f.write("RSA signature test payload")
        sig_file = str(tmp_path / "rsa.sig")
        r_sign = sign_raw(data_file, priv, sig_file)
        assert r_sign.success
        r_verify = verify_raw(data_file, sig_file, pub)
        assert r_verify.success
        assert r_verify.parsed.get("verified")

    def test_batch_sign(self, signing_setup, tmp_path):
        from modules.signing.controller import batch_sign
        batch_dir = tmp_path / "batch"
        batch_dir.mkdir()
        for i in range(3):
            (batch_dir / f"file{i}.txt").write_text(f"File {i} content")
        results = batch_sign(
            str(batch_dir), "*.txt",
            signing_setup["priv"], signing_setup["cert"]
        )
        assert len(results) == 3
        for r in results:
            assert r.success, f"Batch sign failed: {r.stderr}"
        # .p7s files should exist
        p7s_files = list(batch_dir.glob("*.p7s"))
        assert len(p7s_files) == 3


# ---------------------------------------------------------------------------
# S/MIME: sign/verify, encrypt/decrypt
# ---------------------------------------------------------------------------

class TestSMIME:
    @pytest.fixture
    def rsa_setup(self, tmp_path):
        """RSA key + self-signed cert for S/MIME (RSA required for encryption)."""
        from modules.keymgmt.controller import generate_key
        from modules.pki.controller import create_self_signed
        priv = str(tmp_path / "smime_key.pem")
        generate_key("RSA-2048", None, priv)
        cert = str(tmp_path / "smime_cert.pem")
        create_self_signed(priv, cert, {"CN": "SMIME Test", "C": "IN"}, days=365)
        return {"priv": priv, "cert": cert, "tmp_path": tmp_path}

    def test_smime_sign_and_verify(self, rsa_setup):
        from modules.smime.controller import sign_message, verify_message
        msg = str(rsa_setup["tmp_path"] / "message.txt")
        with open(msg, "w") as f:
            f.write("Hello, this is an S/MIME signed message.")
        signed = str(rsa_setup["tmp_path"] / "signed.p7s")
        r_sign = sign_message(msg, rsa_setup["priv"], rsa_setup["cert"], signed)
        assert r_sign.success, f"S/MIME sign failed: {r_sign.stderr}"
        assert os.path.exists(signed)

        r_verify = verify_message(signed)  # uses -noverify (no CA bundle)
        assert r_verify.success, f"S/MIME verify failed: {r_verify.stderr}"
        assert r_verify.parsed.get("verified") is True

    def test_smime_encrypt_and_decrypt(self, rsa_setup):
        from modules.smime.controller import encrypt_message, decrypt_message
        msg = str(rsa_setup["tmp_path"] / "plaintext.txt")
        plaintext_content = "Secret S/MIME encrypted message"
        with open(msg, "w") as f:
            f.write(plaintext_content)
        enc = str(rsa_setup["tmp_path"] / "encrypted.p7m")
        dec = str(rsa_setup["tmp_path"] / "decrypted.txt")

        r_enc = encrypt_message(msg, rsa_setup["cert"], enc)
        assert r_enc.success, f"S/MIME encrypt failed: {r_enc.stderr}"
        assert os.path.exists(enc)

        r_dec = decrypt_message(enc, rsa_setup["priv"], rsa_setup["cert"], dec)
        assert r_dec.success, f"S/MIME decrypt failed: {r_dec.stderr}"
        assert plaintext_content in open(dec).read()

    def test_smime_decrypt_wrong_key_fails(self, rsa_setup, tmp_path):
        from modules.keymgmt.controller import generate_key
        from modules.smime.controller import encrypt_message, decrypt_message
        msg = str(rsa_setup["tmp_path"] / "msg.txt")
        with open(msg, "w") as f:
            f.write("confidential")
        enc = str(rsa_setup["tmp_path"] / "enc_wrong.p7m")
        dec = str(rsa_setup["tmp_path"] / "dec_wrong.txt")
        encrypt_message(msg, rsa_setup["cert"], enc)

        # Generate a different key
        wrong_key = str(tmp_path / "wrong_key.pem")
        generate_key("RSA-2048", None, wrong_key)
        r_dec = decrypt_message(enc, wrong_key, rsa_setup["cert"], dec)
        assert not r_dec.success, "Decryption with wrong key should fail"

    def test_smime_sign_detached_false(self, rsa_setup):
        """Embedded (non-detached) S/MIME signature."""
        from modules.smime.controller import sign_message, verify_message
        msg = str(rsa_setup["tmp_path"] / "embedded_msg.txt")
        with open(msg, "w") as f:
            f.write("Embedded S/MIME message")
        signed = str(rsa_setup["tmp_path"] / "embedded.p7m")
        r_sign = sign_message(msg, rsa_setup["priv"], rsa_setup["cert"], signed, detached=False)
        assert r_sign.success, f"Embedded S/MIME sign failed: {r_sign.stderr}"
        r_verify = verify_message(signed)
        assert r_verify.success, f"Embedded S/MIME verify failed: {r_verify.stderr}"


# ---------------------------------------------------------------------------
# TLS: config builder and rater (no network required)
# ---------------------------------------------------------------------------

class TestTLSConfig:
    def test_build_nginx_intermediate(self):
        from modules.tls.controller import build_config
        config = build_config("nginx", "intermediate")
        assert "TLSv1.2" in config
        assert "TLSv1.3" in config
        assert "ssl_protocols" in config

    def test_build_nginx_modern(self):
        from modules.tls.controller import build_config
        config = build_config("nginx", "modern")
        assert "TLSv1.3" in config
        assert "TLSv1.2" not in config.splitlines()[1]  # modern = TLS 1.3 only

    def test_build_apache_intermediate(self):
        from modules.tls.controller import build_config
        config = build_config("apache", "intermediate")
        assert "SSLProtocol" in config
        assert "SSLCipherSuite" in config

    def test_build_haproxy_intermediate(self):
        from modules.tls.controller import build_config
        config = build_config("haproxy", "intermediate")
        assert "ssl-default-bind-ciphers" in config

    def test_build_postfix_intermediate(self):
        from modules.tls.controller import build_config
        config = build_config("postfix", "intermediate")
        assert "smtpd_tls" in config

    def test_build_unknown_server_returns_fallback(self):
        from modules.tls.controller import build_config
        config = build_config("unknown_server_xyz", "intermediate")
        assert config  # should return something, not raise

    def test_rate_config_a_plus(self):
        from modules.tls.controller import rate_config
        result = rate_config(
            ["TLSv1.2", "TLSv1.3"],
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"
        )
        assert result["grade"] in ("A+", "A")
        assert result["score"] >= 80

    def test_rate_config_f_grade_sslv3(self):
        from modules.tls.controller import rate_config
        result = rate_config(["SSLv3"], "RC4-MD5")
        assert result["grade"] == "F"
        assert result["score"] < 60

    def test_rate_config_tls10_degrades(self):
        from modules.tls.controller import rate_config
        result_no_tls10 = rate_config(["TLSv1.2", "TLSv1.3"], "ECDHE-RSA-AES256-GCM-SHA384")
        result_with_tls10 = rate_config(["TLSv1.0", "TLSv1.2"], "ECDHE-RSA-AES256-GCM-SHA384")
        assert result_no_tls10["score"] > result_with_tls10["score"]

    def test_rate_config_rc4_detected(self):
        from modules.tls.controller import rate_config
        result = rate_config(["TLSv1.2"], "ECDHE-RSA-RC4-SHA")
        issues_text = " ".join(result["issues"]).lower()
        assert "rc4" in issues_text

    def test_rate_config_issues_list(self):
        from modules.tls.controller import rate_config
        result = rate_config(["TLSv1.0", "TLSv1.1"], "3DES-SHA:EXPORT-RC4")
        assert len(result["issues"]) > 0

    def test_rate_config_returns_all_keys(self):
        from modules.tls.controller import rate_config
        result = rate_config(["TLSv1.3"], "TLS_AES_256_GCM_SHA384")
        assert "grade" in result
        assert "score" in result
        assert "issues" in result
        assert "recommendations" in result
        assert "mozilla_profile" in result

    def test_rate_config_tls13_only_is_modern(self):
        from modules.tls.controller import rate_config
        result = rate_config(["TLSv1.3"], "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
        assert result["mozilla_profile"] == "Modern"


# ---------------------------------------------------------------------------
# Random: extended
# ---------------------------------------------------------------------------

class TestRandomExtended:
    def test_random_bytes_base64(self):
        from modules.random.controller import random_bytes
        r = random_bytes(32, "base64")
        assert r.success
        val = r.parsed.get("value", "")
        assert val  # should not be empty
        import base64
        try:
            decoded = base64.b64decode(val + "==")
            assert len(decoded) > 0
        except Exception:
            pytest.fail("base64 random output is not valid base64")

    def test_random_bytes_entropy_bits(self):
        from modules.random.controller import random_bytes
        r = random_bytes(16, "hex")
        assert r.parsed.get("entropy_bits") == 128  # 16 bytes * 8 bits

    def test_random_prime_512(self):
        from modules.random.controller import random_prime
        r = random_prime(bits=512)
        assert r.success, f"random_prime 512 failed: {r.stderr}"
        prime = r.parsed.get("prime", "")
        assert prime  # should have a prime value

    def test_random_prime_is_large(self):
        from modules.random.controller import random_prime
        r = random_prime(bits=256)
        assert r.success
        prime_str = r.parsed.get("prime", "0")
        # Strip any hex prefix
        prime_val = int(prime_str.replace(":", "").replace(" ", "").strip(), 16) if ":" in prime_str else int(prime_str.strip())
        assert prime_val > 2 ** 200  # 256-bit prime is certainly > 2^200

    def test_entropy_estimate_base64(self):
        from modules.random.controller import entropy_estimate
        import base64
        val = base64.b64encode(b"test" * 8).decode()  # valid base64
        result = entropy_estimate(val)
        assert result["charset"] == "base64"
        assert result["bits_per_char"] == 6.0

    def test_entropy_estimate_custom_charset(self):
        from modules.random.controller import entropy_estimate
        import math
        # Use a non-hex, non-base64 string so the charset detection falls through to assumed_charset_size
        result = entropy_estimate("hello world!", assumed_charset_size=95)
        expected = round(math.log2(95) * 12, 1)
        assert result["entropy_bits"] == expected

    def test_entropy_estimate_empty_string(self):
        from modules.random.controller import entropy_estimate
        result = entropy_estimate("")
        assert result["entropy_bits"] == 0

    def test_random_password_no_symbols(self):
        from modules.random.controller import random_password
        r = random_password(length=16, use_symbols=False)
        assert r.success
        pw = r.parsed.get("password", "")
        assert len(pw) == 16
        # No symbols
        for ch in pw:
            assert ch.isalnum(), f"Expected alphanumeric only, got '{ch}'"

    def test_random_password_entropy_grows_with_length(self):
        from modules.random.controller import random_password
        r_short = random_password(length=8)
        r_long = random_password(length=32)
        assert r_long.parsed["entropy_bits"] > r_short.parsed["entropy_bits"]

    def test_random_uuid_format(self):
        from modules.random.controller import random_uuid
        r = random_uuid()
        assert r.success
        uid = r.parsed.get("uuid", "")
        assert len(uid) == 36
        parts = uid.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert len(parts[2]) == 4
        assert len(parts[3]) == 4
        assert len(parts[4]) == 12
        assert uid[14] == "4"  # UUID version 4


# ---------------------------------------------------------------------------
# GPG: graceful handling (may or may not be installed)
# ---------------------------------------------------------------------------

class TestGPG:
    def test_list_keys_returns_result(self):
        from modules.gpg.controller import list_keys
        r = list_keys(secret=False)
        assert isinstance(r, ExecutionResult)
        # Either succeeds (gpg installed) or returns a helpful error
        if not r.success:
            assert r.stderr  # must say something

    def test_list_secret_keys_returns_result(self):
        from modules.gpg.controller import list_keys
        r = list_keys(secret=True)
        assert isinstance(r, ExecutionResult)

    def test_generate_key_without_gpg_returns_graceful_failure(self):
        """If gpg is not available, generate_key_batch must fail gracefully."""
        from modules.gpg.controller import generate_key_batch
        r = generate_key_batch("Test User", "test@example.com", algorithm="ed25519")
        assert isinstance(r, ExecutionResult)
        # May succeed or fail, but must not raise an exception


# ---------------------------------------------------------------------------
# Secure Temp File: additional edge cases
# ---------------------------------------------------------------------------

class TestSecureTempFileExtended:
    def test_write_bytes_and_read(self):
        with secure_temp_file(suffix=".bin") as tf:
            tf.write(b"\x00\x01\x02\x03\xff")
            assert tf.read() == b"\x00\x01\x02\x03\xff"

    def test_write_replaces_content(self):
        with secure_temp_file(suffix=".txt") as tf:
            tf.write(b"first write")
            tf.write(b"second write")
            assert tf.read() == b"second write"

    def test_read_text(self):
        with secure_temp_file(suffix=".txt", content=b"hello text") as tf:
            text = tf.read_text()
            assert text == "hello text"

    def test_secure_delete_overwrites(self):
        """After secure_delete, the file should not exist."""
        tf = SecureTempFile(suffix=".pem")
        tf.write(b"sensitive key material")
        path = tf.path
        tf.secure_delete()
        assert not os.path.exists(path)

    def test_multiple_temp_files_independent(self):
        with secure_temp_file(content=b"file1") as tf1:
            with secure_temp_file(content=b"file2") as tf2:
                assert tf1.path != tf2.path
                assert tf1.read() == b"file1"
                assert tf2.read() == b"file2"


# ---------------------------------------------------------------------------
# Security: additional injection/safety tests
# ---------------------------------------------------------------------------

class TestSecurity:
    def test_passphrase_not_in_command_str(self, tmp_path):
        """Passphrase must never appear in the display-safe command string."""
        from modules.keymgmt.controller import generate_key
        priv = str(tmp_path / "masked.pem")
        r = generate_key("Ed25519", "super_secret_passphrase_123", priv)
        assert "super_secret_passphrase_123" not in r.command_str

    def test_shell_injection_in_filename(self):
        """Files with shell metacharacters must be treated as literal filenames."""
        from modules.hashing.controller import hash_file
        r = hash_file("/dev/null; echo INJECTED")
        assert not r.success
        combined = (r.stdout + r.stderr)
        lines = combined.splitlines()
        assert not any(l.strip() == "INJECTED" for l in lines)

    def test_no_shell_in_symmetric_encrypt(self, tmp_path):
        """Shell metacharacters in passphrase are not executed."""
        from modules.symmetric.controller import encrypt_file
        plain = tmp_path / "plain.txt"
        plain.write_bytes(b"test")
        enc = str(tmp_path / "enc.bin")
        r = encrypt_file(str(plain), enc, "AES-256-GCM", "pass$(echo HACKED)")
        # Either succeeds with the literal passphrase or fails — no shell execution
        combined = r.stdout + r.stderr
        assert "HACKED" not in combined
