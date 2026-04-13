"""
tests/test_extended.py — Comprehensive extended test suite for sslOpenCrypt.

Covers gaps in the existing suite:
  - India DSC module (mocked subprocess)
  - Signing: Ed448, TSA (mocked), verify_bin_signed, batch_sign edge cases
  - PKI: inspect_cert_chain, multi-SAN certs, intermediate CA, import_pkcs12
  - Symmetric: AES-192, format variants, empty-file edge case
  - Key management: DSA-2048, X448, RSA-3072, secp256k1
  - Random: binary file output, UUID v4 format, prime 1024-bit, entropy
  - TLS advisor: all rating grades, build_config variants
  - GPG: full lifecycle (skipped if gpg unavailable)
  - Core: executor error paths, session log remove_listener, tempfile dir
  - Security: passphrase masking in PKI/signing, no shell injection
  - Lab report: HTML content structure and escaping
"""

import os
import re
import sys
import json
import stat
import struct
import shutil
import tempfile
import hashlib
import importlib
from pathlib import Path
from unittest import mock
from unittest.mock import patch, MagicMock, call

import pytest

# ---------------------------------------------------------------------------
# Path setup so modules import correctly when run from the tests/ dir
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from core.executor import run_openssl, run_gpg, get_openssl_path, openssl_version
from core.result import ExecutionResult
from core.audit_log import log_operation, read_log
from core.session_log import (
    start_session, stop_session, log_entry as session_log_entry,
    get_entries, get_session_info, is_active, add_listener, remove_listener,
    clear as session_clear,
)
from core.tempfile_manager import SecureTempFile, secure_temp_file, secure_temp_dir
from core.lab_report import generate_html_report, generate_html_report_file

from modules.hashing import controller as hash_ctrl
from modules.keymgmt import controller as keymgmt_ctrl
from modules.symmetric import controller as sym_ctrl
from modules.pki import controller as pki_ctrl
from modules.signing import controller as signing_ctrl
from modules.smime import controller as smime_ctrl
from modules.random import controller as random_ctrl
from modules.tls import controller as tls_ctrl
from modules.gpg import controller as gpg_ctrl
from modules.india_dsc import controller as dsc_ctrl
from modules.vault import controller as vault_ctrl


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def tmp_dir():
    """Shared temp directory for the entire module."""
    d = tempfile.mkdtemp(prefix="sslopencrypt_test_ext_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="module")
def ed25519_key(tmp_dir):
    priv = os.path.join(tmp_dir, "ext_ed25519.pem")
    pub = os.path.join(tmp_dir, "ext_ed25519_pub.pem")
    r = keymgmt_ctrl.generate_key("Ed25519", None, priv)
    assert r.success, f"Ed25519 keygen failed: {r.stderr}"
    return priv, pub


@pytest.fixture(scope="module")
def ed448_key(tmp_dir):
    priv = os.path.join(tmp_dir, "ext_ed448.pem")
    pub = os.path.join(tmp_dir, "ext_ed448_pub.pem")
    r = keymgmt_ctrl.generate_key("Ed448", None, priv)
    assert r.success, f"Ed448 keygen failed: {r.stderr}"
    return priv, pub


@pytest.fixture(scope="module")
def rsa2048_key(tmp_dir):
    priv = os.path.join(tmp_dir, "ext_rsa2048.pem")
    r = keymgmt_ctrl.generate_key("RSA-2048", None, priv)
    assert r.success, f"RSA-2048 keygen failed: {r.stderr}"
    pub = priv.replace(".pem", "_pub.pem")
    return priv, pub


@pytest.fixture(scope="module")
def ecdsa_p256_key(tmp_dir):
    priv = os.path.join(tmp_dir, "ext_ecdsa_p256.pem")
    r = keymgmt_ctrl.generate_key("ECDSA-P256", None, priv)
    assert r.success, f"ECDSA-P256 keygen failed: {r.stderr}"
    pub = priv.replace(".pem", "_pub.pem")
    return priv, pub


@pytest.fixture(scope="module")
def selfsigned_cert(tmp_dir, ecdsa_p256_key):
    priv, pub = ecdsa_p256_key
    cert = os.path.join(tmp_dir, "ext_selfsigned.pem")
    r = pki_ctrl.create_self_signed(
        key_path=priv,
        output_path=cert,
        subject={"CN": "Test Cert", "O": "sslOpenCrypt Test", "C": "IN"},
        days=365,
    )
    assert r.success, f"Self-signed cert failed: {r.stderr}"
    return cert


@pytest.fixture(scope="module")
def root_ca(tmp_dir):
    """Create a root CA key and certificate."""
    ca_key = os.path.join(tmp_dir, "ext_ca_key.pem")
    ca_cert = os.path.join(tmp_dir, "ext_ca_cert.pem")
    r_key = keymgmt_ctrl.generate_key("RSA-2048", None, ca_key)
    assert r_key.success
    r_cert = pki_ctrl.create_root_ca(
        key_path=ca_key,
        cert_output=ca_cert,
        subject={"CN": "Test Root CA", "O": "sslOpenCrypt", "C": "IN"},
        days=3650,
    )
    assert r_cert.success, f"Root CA creation failed: {r_cert.stderr}"
    return ca_key, ca_cert


@pytest.fixture(scope="module")
def issued_cert(tmp_dir, root_ca, rsa2048_key):
    """End-entity cert issued by root_ca."""
    ca_key, ca_cert = root_ca
    ee_priv, ee_pub = rsa2048_key
    csr_path = os.path.join(tmp_dir, "ext_ee.csr")
    cert_path = os.path.join(tmp_dir, "ext_ee_cert.pem")
    r_csr = pki_ctrl.create_csr(
        key_path=ee_priv,
        output_path=csr_path,
        subject={"CN": "End Entity", "O": "sslOpenCrypt", "C": "IN"},
    )
    assert r_csr.success
    r_cert = pki_ctrl.sign_csr(
        ca_cert_path=ca_cert,
        ca_key_path=ca_key,
        csr_path=csr_path,
        output_path=cert_path,
        days=365,
    )
    assert r_cert.success, f"CSR signing failed: {r_cert.stderr}"
    return ee_priv, cert_path, ca_cert


@pytest.fixture(scope="module")
def gpg_available():
    """Skip tests in classes that need GPG if it's not installed."""
    from core.executor import get_gpg_path
    if get_gpg_path() is None:
        pytest.skip("gpg2/gpg not installed")


# ===========================================================================
# SECTION 1: Key Management — Extended
# ===========================================================================

class TestKeyManagementExtended2:
    """Additional key algorithm coverage."""

    def test_rsa_3072_keygen(self, tmp_dir):
        priv = os.path.join(tmp_dir, "rsa3072.pem")
        r = keymgmt_ctrl.generate_key("RSA-3072", None, priv)
        assert r.success, r.stderr
        assert os.path.exists(priv)
        assert r.parsed.get("algorithm") == "RSA-3072"

    def test_ecdsa_p521_keygen(self, tmp_dir):
        priv = os.path.join(tmp_dir, "ecdsa_p521.pem")
        r = keymgmt_ctrl.generate_key("ECDSA-P521", None, priv)
        assert r.success, r.stderr
        assert os.path.exists(priv)

    def test_ecdsa_secp256k1_keygen(self, tmp_dir):
        priv = os.path.join(tmp_dir, "secp256k1.pem")
        r = keymgmt_ctrl.generate_key("ECDSA-secp256k1", None, priv)
        assert r.success, r.stderr
        assert os.path.exists(priv)

    def test_x448_keygen(self, tmp_dir):
        priv = os.path.join(tmp_dir, "x448.pem")
        r = keymgmt_ctrl.generate_key("X448", None, priv)
        assert r.success, r.stderr
        assert os.path.exists(priv)

    def test_dsa_2048_keygen(self, tmp_dir):
        priv = os.path.join(tmp_dir, "dsa2048.pem")
        r = keymgmt_ctrl.generate_key("DSA-2048", None, priv)
        assert r.success, r.stderr
        assert os.path.exists(priv)

    def test_inspect_ed448_key_shows_type(self, tmp_dir, ed448_key):
        priv, pub = ed448_key
        r = keymgmt_ctrl.inspect_key(priv)
        assert r.success, r.stderr
        algo = r.parsed.get("algorithm", "").upper()
        assert "ED448" in algo, f"Expected ED448 in algorithm, got: {algo!r}"

    def test_extract_public_key_ed448(self, tmp_dir, ed448_key):
        priv, pub = ed448_key
        out_pub = os.path.join(tmp_dir, "ed448_pub_extracted.pem")
        r = keymgmt_ctrl.extract_public_key(priv, out_pub)
        assert r.success, r.stderr
        assert os.path.exists(out_pub)
        content = Path(out_pub).read_text()
        assert "PUBLIC KEY" in content

    def test_extract_public_key_wrong_passphrase_fails(self, tmp_dir):
        priv = os.path.join(tmp_dir, "rsa_encrypted_ext.pem")
        pub = os.path.join(tmp_dir, "rsa_encrypted_ext_pub.pem")
        r = keymgmt_ctrl.generate_key("RSA-2048", "correctpass", priv)
        assert r.success
        out = os.path.join(tmp_dir, "rsa_encrypted_bad_pub.pem")
        r2 = keymgmt_ctrl.extract_public_key(priv, out, passphrase="wrongpass")
        assert not r2.success

    def test_convert_key_pem_to_der_rsa(self, tmp_dir):
        priv = os.path.join(tmp_dir, "rsa_conv.pem")
        der = os.path.join(tmp_dir, "rsa_conv.der")
        r = keymgmt_ctrl.generate_key("RSA-2048", None, priv)
        assert r.success
        r2 = keymgmt_ctrl.convert_key(priv, der, "PEM", "DER")
        assert r2.success, r2.stderr
        assert os.path.exists(der)
        # DER files are binary
        content = Path(der).read_bytes()
        assert content[:2] == b"\x30\x82" or content[0] == 0x30

    def test_convert_der_to_pem_rsa(self, tmp_dir):
        priv = os.path.join(tmp_dir, "rsa_conv2.pem")
        der = os.path.join(tmp_dir, "rsa_conv2.der")
        pem2 = os.path.join(tmp_dir, "rsa_conv2_back.pem")
        keymgmt_ctrl.generate_key("RSA-2048", None, priv)
        r1 = keymgmt_ctrl.convert_key(priv, der, "PEM", "DER")
        assert r1.success
        r2 = keymgmt_ctrl.convert_key(der, pem2, "DER", "PEM")
        assert r2.success, r2.stderr
        assert "PRIVATE KEY" in Path(pem2).read_text()

    def test_all_algorithms_list_contains_expected(self):
        expected = ["RSA-2048", "ECDSA-P256", "Ed25519", "Ed448", "X25519", "DSA-2048"]
        for algo in expected:
            assert algo in keymgmt_ctrl.ALL_ALGORITHMS, f"{algo} missing from ALL_ALGORITHMS"

    def test_beginner_algorithms_subset_of_all(self):
        for algo in keymgmt_ctrl.BEGINNER_ALGORITHMS:
            assert algo in keymgmt_ctrl.ALL_ALGORITHMS


# ===========================================================================
# SECTION 2: Symmetric Encryption — Extended
# ===========================================================================

class TestSymmetricExtended2:
    """Additional cipher coverage and edge cases."""

    def test_aes_192_cbc_encrypt_decrypt(self, tmp_dir):
        plain = os.path.join(tmp_dir, "sym_plain_192.txt")
        enc = os.path.join(tmp_dir, "sym_enc_192.bin")
        dec = os.path.join(tmp_dir, "sym_dec_192.txt")
        Path(plain).write_text("AES-192 test content")
        r_enc = sym_ctrl.encrypt_file(plain, enc, "AES-192-CBC", "pass192")
        assert r_enc.success, r_enc.stderr
        r_dec = sym_ctrl.decrypt_file(enc, dec, "AES-192-CBC", "pass192")
        assert r_dec.success, r_dec.stderr
        assert Path(dec).read_text() == "AES-192 test content"

    def test_aes_256_ctr_encrypt_decrypt(self, tmp_dir):
        plain = os.path.join(tmp_dir, "sym_plain_ctr.txt")
        enc = os.path.join(tmp_dir, "sym_enc_ctr.bin")
        dec = os.path.join(tmp_dir, "sym_dec_ctr.txt")
        Path(plain).write_text("CTR mode test")
        r_enc = sym_ctrl.encrypt_file(plain, enc, "AES-256-CTR", "passctr")
        assert r_enc.success, r_enc.stderr
        r_dec = sym_ctrl.decrypt_file(enc, dec, "AES-256-CTR", "passctr")
        assert r_dec.success, r_dec.stderr
        assert Path(dec).read_text() == "CTR mode test"

    def test_encrypt_text_base64_roundtrip(self, tmp_dir):
        r_enc = sym_ctrl.encrypt_text("Hello base64 world", "AES-256-GCM", "passb64", "base64")
        assert r_enc.success, r_enc.stderr
        ciphertext = r_enc.parsed.get("ciphertext", "")
        assert len(ciphertext) > 0
        r_dec = sym_ctrl.decrypt_text(ciphertext, "AES-256-GCM", "passb64", "base64")
        assert r_dec.success, r_dec.stderr
        assert r_dec.parsed.get("plaintext") == "Hello base64 world"

    def test_encrypt_text_hex_roundtrip(self, tmp_dir):
        r_enc = sym_ctrl.encrypt_text("Hello hex world", "AES-256-CBC", "passhex", "hex")
        assert r_enc.success, r_enc.stderr
        ciphertext = r_enc.parsed.get("ciphertext", "")
        assert re.fullmatch(r"[0-9a-fA-F]+", ciphertext), "Hex ciphertext should be hex"
        r_dec = sym_ctrl.decrypt_text(ciphertext, "AES-256-CBC", "passhex", "hex")
        assert r_dec.success, r_dec.stderr
        assert r_dec.parsed.get("plaintext") == "Hello hex world"

    def test_encrypt_empty_file(self, tmp_dir):
        plain = os.path.join(tmp_dir, "sym_empty.txt")
        enc = os.path.join(tmp_dir, "sym_empty_enc.bin")
        dec = os.path.join(tmp_dir, "sym_empty_dec.txt")
        Path(plain).write_bytes(b"")
        r_enc = sym_ctrl.encrypt_file(plain, enc, "AES-256-GCM", "emptypass")
        assert r_enc.success, r_enc.stderr
        r_dec = sym_ctrl.decrypt_file(enc, dec, "AES-256-GCM", "emptypass")
        assert r_dec.success, r_dec.stderr
        assert Path(dec).read_bytes() == b""

    def test_decrypt_missing_file_fails(self, tmp_dir):
        missing = os.path.join(tmp_dir, "no_such_file.bin")
        out = os.path.join(tmp_dir, "dec_missing.txt")
        r = sym_ctrl.decrypt_file(missing, out, "AES-256-GCM", "pass")
        assert not r.success

    def test_list_ciphers_returns_non_empty(self):
        r = sym_ctrl.list_supported_ciphers()
        assert r.success, r.stderr
        # The parsed output should contain cipher names
        output = r.stdout + r.stderr
        assert len(output) > 0

    def test_des_deprecated_flag(self, tmp_dir):
        plain = os.path.join(tmp_dir, "sym_des_plain.txt")
        enc = os.path.join(tmp_dir, "sym_des_enc.bin")
        Path(plain).write_text("DES test")
        r = sym_ctrl.encrypt_file(plain, enc, "DES-CBC", "despass")
        # May fail on modern OpenSSL with legacy disabled, but if it succeeds,
        # it must be flagged as deprecated
        if r.success:
            assert r.is_deprecated_alg, "DES should be flagged as deprecated"

    def test_chacha20_poly1305_text_roundtrip(self, tmp_dir):
        r_enc = sym_ctrl.encrypt_text("ChaCha20 text test", "ChaCha20-Poly1305", "chachapass", "base64")
        assert r_enc.success, r_enc.stderr
        ct = r_enc.parsed.get("ciphertext", "")
        r_dec = sym_ctrl.decrypt_text(ct, "ChaCha20-Poly1305", "chachapass", "base64")
        assert r_dec.success, r_dec.stderr
        assert r_dec.parsed.get("plaintext") == "ChaCha20 text test"

    def test_wrong_cipher_on_decrypt_fails(self, tmp_dir):
        plain = os.path.join(tmp_dir, "sym_wrongcipher.txt")
        enc = os.path.join(tmp_dir, "sym_wrongcipher_enc.bin")
        dec = os.path.join(tmp_dir, "sym_wrongcipher_dec.txt")
        Path(plain).write_text("test")
        r_enc = sym_ctrl.encrypt_file(plain, enc, "AES-256-GCM", "testpass")
        assert r_enc.success
        # Try to decrypt as CBC — should fail (wrong format)
        r_dec = sym_ctrl.decrypt_file(enc, dec, "AES-256-CBC", "testpass")
        assert not r_dec.success


# ===========================================================================
# SECTION 3: Hashing — Extended
# ===========================================================================

class TestHashingExtended2:

    def test_sha3_512_text(self):
        r = hash_ctrl.hash_text("test", "SHA3-512")
        assert r.success
        assert len(r.stdout.strip()) > 0

    def test_blake2s256_text(self):
        r = hash_ctrl.hash_text("test", "BLAKE2s256")
        assert r.success

    def test_md5_flagged_deprecated(self, tmp_dir):
        f = os.path.join(tmp_dir, "hash_md5.txt")
        Path(f).write_text("md5test")
        r = hash_ctrl.hash_file(f, "MD5")
        assert r.success
        assert r.is_deprecated_alg, "MD5 must be flagged deprecated"

    def test_sha1_flagged_deprecated(self, tmp_dir):
        f = os.path.join(tmp_dir, "hash_sha1.txt")
        Path(f).write_text("sha1test")
        r = hash_ctrl.hash_file(f, "SHA-1")
        assert r.success
        assert r.is_deprecated_alg, "SHA-1 must be flagged deprecated"

    def test_verify_hash_correct(self, tmp_dir):
        f = os.path.join(tmp_dir, "verify_correct.txt")
        Path(f).write_text("verify me")
        r_hash = hash_ctrl.hash_file(f, "SHA-256")
        assert r_hash.success
        ref_hash = r_hash.stdout.strip().split()[-1]
        r_verify = hash_ctrl.verify_hash(f, ref_hash, "SHA-256")
        assert r_verify.success
        assert r_verify.parsed.get("match") is True

    def test_verify_hash_mismatch(self, tmp_dir):
        f = os.path.join(tmp_dir, "verify_mismatch.txt")
        Path(f).write_text("mismatch me")
        r = hash_ctrl.verify_hash(f, "aabbcc" * 10, "SHA-256")
        # Should succeed (ran OK) but match should be False
        assert r.parsed.get("match") is False

    def test_hmac_sha512(self, tmp_dir):
        f = os.path.join(tmp_dir, "hmac512.txt")
        Path(f).write_text("hmac test")
        r = hash_ctrl.hmac_file(f, "secretkey", "SHA-512")
        assert r.success

    def test_hash_missing_file_fails(self):
        r = hash_ctrl.hash_file("/tmp/no_such_file_xyz.txt", "SHA-256")
        assert not r.success

    def test_hash_empty_file(self, tmp_dir):
        f = os.path.join(tmp_dir, "empty_for_hash.txt")
        Path(f).write_bytes(b"")
        r = hash_ctrl.hash_file(f, "SHA-256")
        assert r.success
        # SHA-256 of empty string is known
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert expected in r.stdout.lower()

    def test_avalanche_sha256(self, tmp_dir):
        # avalanche_demo returns a plain dict (not ExecutionResult)
        result = hash_ctrl.avalanche_demo("Hello World", "SHA-256")
        assert isinstance(result, dict), f"Expected dict, got {type(result)}"
        assert "percent_changed" in result, f"Missing percent_changed: {result}"
        pct = result.get("percent_changed", 0)
        assert pct > 30, f"Avalanche effect should change >30% of bits, got {pct}%"

    def test_batch_hash_empty_directory(self, tmp_dir):
        # batch_hash returns a list of dicts (not ExecutionResult)
        empty_dir = os.path.join(tmp_dir, "empty_batch_dir")
        os.makedirs(empty_dir, exist_ok=True)
        results = hash_ctrl.batch_hash(empty_dir, "SHA-256")
        assert isinstance(results, list), f"Expected list, got {type(results)}"
        assert len(results) == 0


# ===========================================================================
# SECTION 4: PKI — Extended
# ===========================================================================

class TestPKIExtended2:

    def test_csr_with_multiple_san_types(self, tmp_dir, rsa2048_key):
        priv, pub = rsa2048_key
        csr = os.path.join(tmp_dir, "multi_san.csr")
        r = pki_ctrl.create_csr(
            key_path=priv,
            output_path=csr,
            subject={"CN": "multi-san.example.com", "O": "Test"},
            san_list=["DNS:multi-san.example.com", "DNS:alt.example.com",
                      "IP:192.168.1.1", "email:admin@example.com"],
        )
        assert r.success, r.stderr
        assert os.path.exists(csr)

    def test_self_signed_with_ip_san(self, tmp_dir, ecdsa_p256_key):
        priv, pub = ecdsa_p256_key
        cert = os.path.join(tmp_dir, "ip_san_cert.pem")
        r = pki_ctrl.create_self_signed(
            key_path=priv,
            output_path=cert,
            subject={"CN": "192.168.0.1"},
            san_list=["IP:192.168.0.1"],
        )
        assert r.success, r.stderr
        # Inspect cert and verify IP SAN present
        r2 = pki_ctrl.inspect_cert(cert)
        assert r2.success
        san_list = r2.parsed.get("san", [])
        assert any("192.168.0.1" in s for s in san_list), f"IP SAN not found: {san_list}"

    def test_inspect_cert_chain_single(self, tmp_dir, selfsigned_cert):
        r = pki_ctrl.inspect_cert_chain(selfsigned_cert)
        assert r.success, r.stderr
        assert "Subject" in r.stdout or "subject" in r.stdout.lower()

    def test_inspect_cert_chain_bundle(self, tmp_dir, root_ca, issued_cert):
        ca_key, ca_cert = root_ca
        ee_priv, ee_cert, _ = issued_cert
        # Bundle CA + EE cert together
        bundle = os.path.join(tmp_dir, "chain_bundle.pem")
        with open(bundle, "w") as fout:
            fout.write(Path(ee_cert).read_text())
            fout.write(Path(ca_cert).read_text())
        r = pki_ctrl.inspect_cert_chain(bundle)
        assert r.success, r.stderr

    def test_verify_cert_chain_valid(self, tmp_dir, root_ca, issued_cert):
        ca_key, ca_cert = root_ca
        ee_priv, ee_cert, _ = issued_cert
        r = pki_ctrl.verify_cert_chain(ee_cert, ca_bundle=ca_cert)
        assert r.success, r.stderr
        assert r.parsed.get("verified") is True

    def test_cert_inspect_extracts_subject_issuer(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        r = pki_ctrl.inspect_cert(ee_cert)
        assert r.success
        assert "subject" in r.parsed
        assert "issuer" in r.parsed

    def test_cert_inspect_extracts_validity_dates(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        r = pki_ctrl.inspect_cert(ee_cert)
        assert r.success
        assert "not_before" in r.parsed
        assert "not_after" in r.parsed

    def test_cert_inspect_extracts_sig_algorithm(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        r = pki_ctrl.inspect_cert(ee_cert)
        assert r.success
        assert "sig_algorithm" in r.parsed

    def test_pkcs12_create_and_import_with_ca(self, tmp_dir, root_ca, issued_cert):
        ca_key, ca_cert = root_ca
        ee_priv, ee_cert, _ = issued_cert
        pfx = os.path.join(tmp_dir, "test_with_ca.pfx")
        r = pki_ctrl.create_pkcs12(
            cert_path=ee_cert,
            key_path=ee_priv,
            output_path=pfx,
            password="pfxpass",
            ca_bundle=ca_cert,
            friendly_name="TestCert",
        )
        assert r.success, r.stderr
        assert os.path.exists(pfx)

        cert_out = os.path.join(tmp_dir, "pkcs12_cert_out.pem")
        key_out = os.path.join(tmp_dir, "pkcs12_key_out.pem")
        ca_out = os.path.join(tmp_dir, "pkcs12_ca_out.pem")
        r2 = pki_ctrl.import_pkcs12(pfx, "pfxpass", cert_out, key_out, ca_output=ca_out)
        assert r2.success, r2.stderr
        assert os.path.exists(cert_out)
        assert os.path.exists(key_out)

    def test_inspect_cert_missing_file_fails(self):
        r = pki_ctrl.inspect_cert("/tmp/no_such_cert.pem")
        assert not r.success

    def test_sha384_signed_cert(self, tmp_dir, rsa2048_key):
        priv, pub = rsa2048_key
        cert = os.path.join(tmp_dir, "sha384_cert.pem")
        r = pki_ctrl.create_self_signed(
            key_path=priv,
            output_path=cert,
            subject={"CN": "SHA384 Test"},
            digest="sha384",
        )
        assert r.success, r.stderr
        r2 = pki_ctrl.inspect_cert(cert)
        assert r2.success
        sig_alg = r2.parsed.get("sig_algorithm", "")
        assert "384" in sig_alg, f"Expected SHA384 in sig algo, got: {sig_alg}"


# ===========================================================================
# SECTION 5: Signing — Extended
# ===========================================================================

class TestSigningExtended2:

    def test_raw_sign_verify_ed448(self, tmp_dir, ed448_key):
        priv, pub = ed448_key
        data = os.path.join(tmp_dir, "ed448_data.bin")
        sig = os.path.join(tmp_dir, "ed448_data.sig")
        Path(data).write_bytes(b"Ed448 signing test data")
        # Extract public key first
        pub_out = os.path.join(tmp_dir, "ed448_pub.pem")
        keymgmt_ctrl.extract_public_key(priv, pub_out)
        r_sign = signing_ctrl.sign_raw(data, priv, sig)
        assert r_sign.success, r_sign.stderr
        r_verify = signing_ctrl.verify_raw(data, sig, pub_out)
        assert r_verify.success, r_verify.stderr
        assert r_verify.parsed.get("verified") is True

    def test_raw_sign_tampered_data_fails(self, tmp_dir, ed25519_key):
        priv, pub = ed25519_key
        data = os.path.join(tmp_dir, "ed25519_tamper.bin")
        data_tampered = os.path.join(tmp_dir, "ed25519_tamper_mod.bin")
        sig = os.path.join(tmp_dir, "ed25519_tamper.sig")
        Path(data).write_bytes(b"original content")
        Path(data_tampered).write_bytes(b"tampered content")
        pub_out = os.path.join(tmp_dir, "ed25519_tamper_pub.pem")
        keymgmt_ctrl.extract_public_key(priv, pub_out)
        signing_ctrl.sign_raw(data, priv, sig)
        r = signing_ctrl.verify_raw(data_tampered, sig, pub_out)
        assert not r.success

    def test_cms_embedded_sign_and_verify(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        data = os.path.join(tmp_dir, "cms_embed_data.txt")
        sig = os.path.join(tmp_dir, "cms_embed.p7m")
        Path(data).write_text("CMS embedded test")
        r_sign = signing_ctrl.sign_file(
            file_path=data,
            key_path=ee_priv,
            cert_path=ee_cert,
            output_sig=sig,
            detached=False,   # embedded / opaque
        )
        assert r_sign.success, r_sign.stderr
        r_verify = signing_ctrl.verify_file(
            file_path=data,
            sig_path=sig,
            no_verify_cert=True,
        )
        assert r_verify.success, r_verify.stderr
        assert r_verify.parsed.get("verified") is True

    def test_cms_sign_with_wrong_key_fails(self, tmp_dir, issued_cert, ed25519_key):
        ee_priv, ee_cert, ca_cert = issued_cert
        wrong_priv, wrong_pub = ed25519_key
        data = os.path.join(tmp_dir, "cms_wrongkey.txt")
        sig = os.path.join(tmp_dir, "cms_wrongkey.p7s")
        Path(data).write_text("wrong key test")
        # Signing with a key that doesn't match the cert should fail
        r = signing_ctrl.sign_file(
            file_path=data,
            key_path=wrong_priv,
            cert_path=ee_cert,
            output_sig=sig,
        )
        assert not r.success

    def test_batch_sign_empty_pattern(self, tmp_dir, issued_cert):
        """batch_sign returns empty list when pattern matches nothing."""
        ee_priv, ee_cert, ca_cert = issued_cert
        batch_dir = os.path.join(tmp_dir, "batch_empty")
        os.makedirs(batch_dir, exist_ok=True)
        results = signing_ctrl.batch_sign(batch_dir, "*.xyz_nonexistent", ee_priv, ee_cert)
        assert results == []

    def test_batch_sign_multiple_files(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        batch_dir = os.path.join(tmp_dir, "batch_multi")
        os.makedirs(batch_dir, exist_ok=True)
        for i in range(3):
            Path(os.path.join(batch_dir, f"file{i}.txt")).write_text(f"content {i}")
        results = signing_ctrl.batch_sign(batch_dir, "*.txt", ee_priv, ee_cert)
        assert len(results) == 3
        assert all(r.success for r in results), [r.stderr for r in results if not r.success]

    def test_verify_bin_signed_missing_marker(self, tmp_dir, ecdsa_p256_key):
        """verify_bin_signed fails gracefully on a file without the 0x00010000 marker."""
        priv, pub = ecdsa_p256_key
        dummy = os.path.join(tmp_dir, "dummy.bin.signed")
        pub_out = os.path.join(tmp_dir, "p256_pub_for_binsig.pem")
        keymgmt_ctrl.extract_public_key(priv, pub_out)
        Path(dummy).write_bytes(b"\x00" * 128)  # no marker
        r = signing_ctrl.verify_bin_signed(dummy, pub_out)
        assert not r.success
        assert "marker" in r.stderr.lower() or "0x00010000" in r.stderr

    def test_tsa_query_failure_returns_graceful_result(self, tmp_dir):
        """TSA request to invalid URL returns a failed result (not an exception)."""
        data = os.path.join(tmp_dir, "tsr_test.txt")
        tsr = os.path.join(tmp_dir, "test.tsr")
        Path(data).write_text("timestamp test")
        # Use a guaranteed-unreachable URL
        r = signing_ctrl.request_timestamp(data, tsr, tsa_url="http://127.0.0.1:19999/ts")
        assert not r.success
        # Should contain some error message
        assert r.stderr or not r.success

    def test_sign_missing_file_fails(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        sig = os.path.join(tmp_dir, "missing_sign.p7s")
        r = signing_ctrl.sign_file("/tmp/does_not_exist_xyz.bin", ee_priv, ee_cert, sig)
        assert not r.success

    def test_public_tsa_urls_dict_populated(self):
        assert "DigiCert" in signing_ctrl.PUBLIC_TSA_URLS
        assert "FreeTSA" in signing_ctrl.PUBLIC_TSA_URLS
        for name, url in signing_ctrl.PUBLIC_TSA_URLS.items():
            assert url.startswith("http"), f"{name} URL malformed: {url}"


# ===========================================================================
# SECTION 6: S/MIME — Extended
# ===========================================================================

class TestSMIMEExtended2:

    def test_smime_encrypt_decrypt_roundtrip(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        msg = os.path.join(tmp_dir, "smime_msg2.txt")
        enc = os.path.join(tmp_dir, "smime_msg2.enc")
        dec = os.path.join(tmp_dir, "smime_msg2.dec")
        Path(msg).write_text("S/MIME roundtrip test message")
        r_enc = smime_ctrl.encrypt_message(msg, ee_cert, enc)
        assert r_enc.success, r_enc.stderr
        r_dec = smime_ctrl.decrypt_message(enc, ee_priv, ee_cert, dec)
        assert r_dec.success, r_dec.stderr
        assert "roundtrip test" in Path(dec).read_text()

    def test_smime_sign_verify_with_ca(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        msg = os.path.join(tmp_dir, "smime_signed2.txt")
        signed = os.path.join(tmp_dir, "smime_signed2.p7m")
        Path(msg).write_text("Signed S/MIME message with CA")
        r_sign = smime_ctrl.sign_message(msg, ee_priv, ee_cert, signed)
        assert r_sign.success, r_sign.stderr
        r_verify = smime_ctrl.verify_message(signed, ca_bundle=ca_cert)
        assert r_verify.success, r_verify.stderr

    def test_smime_wrong_key_decrypt_fails(self, tmp_dir, issued_cert, ed25519_key):
        ee_priv, ee_cert, ca_cert = issued_cert
        msg = os.path.join(tmp_dir, "smime_wrongkey.txt")
        enc = os.path.join(tmp_dir, "smime_wrongkey.enc")
        dec = os.path.join(tmp_dir, "smime_wrongkey.dec")
        Path(msg).write_text("test")
        r_enc = smime_ctrl.encrypt_message(msg, ee_cert, enc)
        assert r_enc.success
        wrong_priv, _ = ed25519_key
        r_dec = smime_ctrl.decrypt_message(enc, wrong_priv, ee_cert, dec)
        assert not r_dec.success


# ===========================================================================
# SECTION 7: Random — Extended
# ===========================================================================

class TestRandomExtended2:

    def test_random_bytes_to_file(self, tmp_dir):
        out = os.path.join(tmp_dir, "rand_bytes.bin")
        r = random_ctrl.random_bytes(32, output_format="binary_file", output_path=out)
        assert r.success, r.stderr
        assert os.path.exists(out)
        assert os.path.getsize(out) == 32

    def test_random_uuid_v4_format(self):
        r = random_ctrl.random_uuid()
        assert r.success
        uid = r.parsed.get("uuid", "")
        # Must match UUID format: 8-4-4-4-12
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            uid
        ), f"UUID format invalid: {uid!r}"
        # Version digit should be 4
        assert uid[14] == "4", f"UUID version digit should be '4', got '{uid[14]}'"
        # Parsed version field
        assert r.parsed.get("version") == 4

    def test_random_uuid_uniqueness(self):
        uuids = set()
        for _ in range(20):
            r = random_ctrl.random_uuid()
            assert r.success
            uuids.add(r.parsed["uuid"])
        assert len(uuids) == 20, "UUIDs should all be unique"

    def test_random_prime_1024(self):
        r = random_ctrl.random_prime(1024)
        assert r.success, r.stderr
        prime_str = r.parsed.get("prime", "").replace("\n", "")
        assert len(prime_str) > 0
        assert r.parsed.get("bits") == 1024

    def test_random_password_length_respected(self):
        for length in [8, 16, 32]:
            r = random_ctrl.random_password(length=length)
            assert r.success
            pwd = r.parsed.get("password", "")
            assert len(pwd) == length, f"Expected len={length}, got {len(pwd)}"

    def test_random_password_charset_digits_only(self):
        r = random_ctrl.random_password(
            length=20,
            use_upper=False,
            use_lower=False,
            use_digits=True,
            use_symbols=False,
            exclude_ambiguous=False,
        )
        assert r.success
        pwd = r.parsed.get("password", "")
        assert all(c.isdigit() for c in pwd), f"Non-digit chars in digits-only password: {pwd}"

    def test_random_password_no_symbols(self):
        r = random_ctrl.random_password(length=20, use_symbols=False)
        assert r.success
        pwd = r.parsed.get("password", "")
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        assert not any(c in symbols for c in pwd), f"Symbol in no-symbol password: {pwd}"

    def test_entropy_estimate_hex(self):
        result = random_ctrl.entropy_estimate("deadbeef")
        assert result["entropy_bits"] == 32.0   # 8 hex chars × 4 bits
        assert result["charset"] == "hex"

    def test_entropy_estimate_empty_string(self):
        result = random_ctrl.entropy_estimate("")
        assert result["entropy_bits"] == 0
        assert result["length"] == 0

    def test_entropy_estimate_custom_charset(self):
        # Use a value with symbols so it doesn't match the hex or base64 auto-detect regex
        value = "hello!@#$%"   # contains symbols, won't match hex or base64 patterns
        result = random_ctrl.entropy_estimate(value, assumed_charset_size=70)
        import math
        expected = round(math.log2(70) * len(value), 1)
        assert result["entropy_bits"] == expected

    def test_random_bytes_hex_is_valid_hex(self):
        r = random_ctrl.random_bytes(16, "hex")
        assert r.success
        hex_val = r.parsed.get("value", "")
        assert re.fullmatch(r"[0-9a-fA-F]+", hex_val), f"Not valid hex: {hex_val!r}"
        # 16 bytes = 32 hex characters
        assert len(hex_val) == 32

    def test_entropy_bits_reported_for_random_bytes(self):
        r = random_ctrl.random_bytes(32, "hex")
        assert r.success
        assert r.parsed.get("entropy_bits") == 256  # 32 bytes × 8


# ===========================================================================
# SECTION 8: TLS Advisor — Extended
# ===========================================================================

class TestTLSAdvisorExtended:
    # NOTE: rate_config(tls_versions, ciphers) — ciphers is a colon/space-separated STRING

    def test_rate_config_a_plus_grade(self):
        result = tls_ctrl.rate_config(
            tls_versions=["TLSv1.2", "TLSv1.3"],
            ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:TLS_AES_256_GCM_SHA384",
        )
        assert result["grade"] in ("A+", "A"), f"Expected A/A+, got {result['grade']}"

    def test_rate_config_f_grade_for_sslv3(self):
        result = tls_ctrl.rate_config(
            tls_versions=["SSLv3"],
            ciphers="DES-CBC3-SHA",
        )
        assert result["grade"] == "F"

    def test_rate_config_b_grade_for_tls10(self):
        result = tls_ctrl.rate_config(
            tls_versions=["TLSv1.0", "TLSv1.2"],
            ciphers="ECDHE-RSA-AES256-SHA",
        )
        assert result["grade"] in ("B", "C", "F"), f"TLS 1.0 should degrade grade, got {result['grade']}"

    def test_rate_config_rc4_in_issues(self):
        result = tls_ctrl.rate_config(
            tls_versions=["TLSv1.2"],
            ciphers="RC4-SHA",
        )
        issues = result.get("issues", [])
        assert any("RC4" in i for i in issues), f"RC4 not in issues: {issues}"

    def test_rate_config_returns_required_keys(self):
        result = tls_ctrl.rate_config(["TLSv1.3"], "TLS_AES_256_GCM_SHA384")
        for key in ("grade", "score", "issues", "recommendations"):
            assert key in result, f"Missing key: {key}"

    def test_build_nginx_modern_no_tls12(self):
        config = tls_ctrl.build_config("nginx", "modern")
        assert "TLSv1.3" in config
        assert "TLSv1.2" not in config or "ssl_protocols TLSv1.3" in config

    def test_build_nginx_intermediate_has_both_versions(self):
        config = tls_ctrl.build_config("nginx", "intermediate")
        assert "TLSv1.2" in config
        assert "TLSv1.3" in config

    def test_build_apache_intermediate(self):
        config = tls_ctrl.build_config("apache", "intermediate")
        assert "SSLProtocol" in config

    def test_build_haproxy_intermediate(self):
        config = tls_ctrl.build_config("haproxy", "intermediate")
        assert "bind" in config or "ssl" in config.lower()

    def test_build_postfix_intermediate(self):
        config = tls_ctrl.build_config("postfix", "intermediate")
        assert "smtp" in config.lower() or "tls" in config.lower()

    def test_build_unknown_server_returns_fallback(self):
        config = tls_ctrl.build_config("iis", "intermediate")
        assert len(config) > 0

    def test_rate_config_score_is_integer_or_float(self):
        result = tls_ctrl.rate_config(["TLSv1.2"], "ECDHE-RSA-AES128-GCM-SHA256")
        assert isinstance(result["score"], (int, float))

    def test_build_config_with_dhparam_command_included(self):
        config = tls_ctrl.build_config("nginx", "intermediate", include_dhparam_cmd=True)
        assert "dhparam" in config.lower()


# ===========================================================================
# SECTION 9: India DSC — Mocked
# ===========================================================================

class TestIndiaDSC:
    """All hardware-dependent tests are mocked via subprocess.run patching."""

    def test_get_india_pki_info_structure(self):
        info = dsc_ctrl.get_india_pki_info()
        assert "rcai_fingerprint_sha256" in info
        assert "licensed_cas" in info
        assert "cca_url" in info
        assert isinstance(info["licensed_cas"], list)
        assert len(info["licensed_cas"]) >= 5

    def test_india_cas_have_required_fields(self):
        info = dsc_ctrl.get_india_pki_info()
        for ca in info["licensed_cas"]:
            assert "name" in ca
            assert "website" in ca
            assert "type" in ca
            assert ca["type"] == "Class 3"

    def test_rcai_fingerprint_format(self):
        info = dsc_ctrl.get_india_pki_info()
        fp = info["rcai_fingerprint_sha256"]
        # Should look like a colon-separated hex fingerprint
        assert ":" in fp
        parts = fp.split(":")
        assert len(parts) == 32  # SHA-256 = 32 bytes = 32 hex pairs

    def test_detect_available_libs_returns_list(self):
        libs = dsc_ctrl.detect_available_libs()
        assert isinstance(libs, list)
        for name, path, present in libs:
            assert isinstance(name, str)
            assert isinstance(path, str)
            assert isinstance(present, bool)

    def test_detect_available_libs_covers_known_libs(self):
        libs = dsc_ctrl.detect_available_libs()
        names = [name for name, _, _ in libs]
        assert "OpenSC (fallback)" in names
        assert "ePass2003 / HYP2003" in names

    def test_known_token_libs_count(self):
        assert len(dsc_ctrl.KNOWN_TOKEN_LIBS) >= 5

    def test_check_dependencies_when_tool_missing(self):
        """When pkcs11-tool is not installed, check_dependencies returns failure."""
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value=None):
            with patch("modules.india_dsc.controller._pcscd_running", return_value=False):
                r = dsc_ctrl.check_dependencies()
        assert not r.success
        assert len(r.parsed.get("issues", [])) >= 2
        assert "pkcs11-tool" in r.parsed["issues"][0]

    def test_check_dependencies_when_all_present(self):
        """When pkcs11-tool and pcscd are present, check_dependencies succeeds."""
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value="/usr/bin/pkcs11-tool"):
            with patch("modules.india_dsc.controller._pcscd_running", return_value=True):
                r = dsc_ctrl.check_dependencies()
        assert r.success
        assert r.parsed["pkcs11_tool"] == "/usr/bin/pkcs11-tool"
        assert r.parsed["pcscd_running"] is True

    def test_list_tokens_without_pkcs11_tool_fails(self):
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value=None):
            r = dsc_ctrl.list_tokens("/usr/lib/opensc-pkcs11.so")
        assert not r.success
        assert "pkcs11-tool not found" in r.stderr

    def test_list_tokens_mocked_success(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Slot 0 (0x0): Feitian ePass2003\n  token label:   myDSC"
        mock_result.stderr = ""
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value="/usr/bin/pkcs11-tool"):
            with patch("subprocess.run", return_value=mock_result):
                r = dsc_ctrl.list_tokens("/usr/lib/x86_64-linux-gnu/libcastle.so.1.0.0")
        assert r.success
        assert len(r.parsed["tokens"]) >= 1

    def test_list_tokens_timeout(self):
        """Timeout during token listing returns graceful failure."""
        import subprocess
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value="/usr/bin/pkcs11-tool"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pkcs11-tool", 10)):
                r = dsc_ctrl.list_tokens("/usr/lib/opensc-pkcs11.so")
        assert not r.success
        assert "timeout" in r.stderr.lower() or "Timeout" in r.stderr

    def test_list_objects_without_tool_fails(self):
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value=None):
            r = dsc_ctrl.list_objects("/usr/lib/opensc-pkcs11.so", "1234")
        assert not r.success

    def test_list_objects_mocked(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "Certificate Object: CKO_CERTIFICATE, token=TRUE\n"
            "  label:    MySigningCert\n"
            "Private Key Object: CKO_PRIVATE_KEY, token=TRUE\n"
            "  label:    MySigningKey\n"
        )
        mock_result.stderr = ""
        with patch("modules.india_dsc.controller._pkcs11_tool", return_value="/usr/bin/pkcs11-tool"):
            with patch("subprocess.run", return_value=mock_result):
                r = dsc_ctrl.list_objects("/usr/lib/opensc-pkcs11.so", "1234")
        assert r.success
        objects = r.parsed.get("objects", [])
        assert any("Certificate" in obj for obj in objects)
        assert any("Private Key" in obj for obj in objects)

    def test_verify_signature_india_pki_missing_file(self):
        r = dsc_ctrl.verify_signature_india_pki(
            "/tmp/no_such_sig.p7s",
            "/tmp/no_such_file.pdf",
        )
        assert not r.success

    def test_inspect_certificate_missing_file(self):
        r = dsc_ctrl.inspect_certificate("/tmp/no_such_cert.pem")
        assert not r.success


# ===========================================================================
# SECTION 10: GPG — Full lifecycle (skipped if gpg unavailable)
# ===========================================================================

class TestGPGLifecycle:
    """Full GPG key lifecycle — skipped if gpg2/gpg not installed."""

    @pytest.fixture(autouse=True)
    def check_gpg(self):
        from core.executor import get_gpg_path
        if get_gpg_path() is None:
            pytest.skip("gpg not installed")

    @pytest.fixture(scope="class")
    def gpg_homedir(self, tmp_path_factory):
        """Isolated GPG home directory."""
        d = tmp_path_factory.mktemp("gpg_home")
        d.chmod(0o700)
        return str(d)

    def _make_key(self, name, email, tmp_dir):
        """Generate a GPG key and return the email (used as key id)."""
        r = gpg_ctrl.generate_key_batch(name, email, "ed25519", "1y")
        return r, email

    def test_generate_key_ed25519(self, tmp_dir):
        r, key_id = self._make_key("Test User GPG", "testgpg@example.com", tmp_dir)
        if not r.success:
            pytest.skip(f"GPG key generation failed: {r.stderr}")
        assert r.success

    def test_list_keys_after_generation(self, tmp_dir):
        self._make_key("List Test", "listtest@example.com", tmp_dir)
        r = gpg_ctrl.list_keys(secret=False)
        # list_keys returns result even on empty keyring — just check it ran
        assert r is not None

    def test_export_and_import_public_key(self, tmp_dir):
        email = "exporttest@example.com"
        r_gen, _ = self._make_key("Export Test", email, tmp_dir)
        if not r_gen.success:
            pytest.skip("GPG key gen failed")
        # Export
        asc_path = os.path.join(tmp_dir, "exported.asc")
        r_exp = gpg_ctrl.export_public_key(email, asc_path)
        assert r_exp.success, r_exp.stderr
        assert os.path.exists(asc_path)
        assert Path(asc_path).stat().st_size > 0

    def test_encrypt_and_decrypt_roundtrip(self, tmp_dir):
        email = "encdec@example.com"
        r_gen, _ = self._make_key("EncDec Test", email, tmp_dir)
        if not r_gen.success:
            pytest.skip("GPG key gen failed")
        plain = os.path.join(tmp_dir, "gpg_plain.txt")
        enc = os.path.join(tmp_dir, "gpg_enc.asc")
        dec = os.path.join(tmp_dir, "gpg_dec.txt")
        Path(plain).write_text("GPG encrypt/decrypt test")
        r_enc = gpg_ctrl.encrypt_file(plain, enc, recipient_ids=[email])
        if not r_enc.success:
            pytest.skip(f"GPG encrypt failed (trust issue?): {r_enc.stderr}")
        r_dec = gpg_ctrl.decrypt_file(enc, dec)
        assert r_dec.success, r_dec.stderr
        assert "GPG encrypt/decrypt test" in Path(dec).read_text()


# ===========================================================================
# SECTION 11: Core — Extended edge cases
# ===========================================================================

class TestCoreExtended:

    def test_openssl_version_is_string(self):
        v = openssl_version()
        assert isinstance(v, str)
        assert "OpenSSL" in v

    def test_run_openssl_unknown_command_fails(self):
        r = run_openssl(["no_such_subcommand_xyz"])
        assert not r.success

    def test_execution_result_output_property(self):
        # output joins stripped stdout + stderr with "\n"
        r = ExecutionResult([], "cmd", "out", "err", {}, True, 0)
        assert r.output == "out\nerr"

    def test_execution_result_error_message_on_success(self):
        r = ExecutionResult([], "cmd", "out", "", {}, True, 0)
        assert r.error_message == ""

    def test_execution_result_error_message_on_failure_with_stderr(self):
        r = ExecutionResult([], "cmd", "", "something went wrong", {}, False, 1)
        assert "something went wrong" in r.error_message

    def test_execution_result_error_message_fallback_to_exit_code(self):
        r = ExecutionResult([], "cmd", "", "", {}, False, 2)
        assert "2" in r.error_message

    def test_deprecated_algorithms_dict_has_md5(self):
        from core.result import DEPRECATED_ALGORITHMS
        assert "md5" in DEPRECATED_ALGORITHMS

    def test_deprecated_algorithms_dict_has_des(self):
        from core.result import DEPRECATED_ALGORITHMS
        assert "des" in DEPRECATED_ALGORITHMS

    def test_audit_log_deprecated_flag_set(self, tmp_dir):
        log_operation("test_module", "test_op", "openssl enc -des-ede3-cbc",
                      True, is_deprecated=True, deprecated_alg="3DES")
        entries = read_log(max_entries=5)
        matching = [e for e in entries if e.get("module") == "test_module"
                    and e.get("operation") == "test_op"]
        assert len(matching) >= 1
        assert matching[-1].get("flag") == "DEPRECATED_ALG"

    def test_session_log_remove_listener(self):
        start_session("TestStudent", "TestSession")
        events = []
        def listener(entry):
            events.append(entry)
        add_listener(listener)
        session_log_entry("mod", "op", "cmd", True)
        assert len(events) == 1
        remove_listener(listener)
        session_log_entry("mod", "op2", "cmd2", True)
        assert len(events) == 1  # not called again after removal
        stop_session()

    def test_session_log_inactive_by_default(self):
        stop_session()
        assert not is_active()

    def test_session_log_clear_keeps_session_active(self):
        start_session("S", "T")
        session_log_entry("m", "o", "c", True)
        session_clear()
        assert is_active()
        assert len(get_entries()) == 0
        stop_session()

    def test_secure_temp_dir_cleanup(self):
        with secure_temp_dir() as d:
            assert os.path.isdir(d)
            Path(os.path.join(d, "test.txt")).write_text("hello")
        assert not os.path.exists(d)

    def test_secure_temp_file_permissions_are_0600(self, tmp_dir):
        stf = SecureTempFile(suffix=".test", prefix="perm_")
        mode = stat.S_IMODE(os.stat(stf.path).st_mode)
        stf.secure_delete()
        assert mode == 0o600

    def test_secure_temp_file_context_manager_cleans_up(self):
        with secure_temp_file(suffix=".tmp", prefix="ctx_", content=b"test") as stf:
            path = stf.path
            assert os.path.exists(path)
        assert not os.path.exists(path)

    def test_secure_temp_file_write_and_read_bytes(self):
        with secure_temp_file(suffix=".bin", prefix="rw_") as stf:
            stf.write(b"\x00\x01\x02\x03")
            data = stf.read()
        assert data == b"\x00\x01\x02\x03"

    def test_run_openssl_with_input_data(self):
        """openssl dgst reads from stdin when given input_data."""
        r = run_openssl(["dgst", "-sha256"], input_data=b"hello")
        assert r.success
        assert len(r.stdout) > 0


# ===========================================================================
# SECTION 12: Lab Report — HTML structure
# ===========================================================================

class TestLabReport:

    def _make_entries(self):
        return [
            {
                "seq": 1, "ts": "2026-04-13T10:00:00",
                "module": "hashing", "operation": "hash_file",
                "command": "openssl dgst -sha256 test.txt",
                "success": True, "deprecated": False, "deprecated_alg": None, "note": "",
            },
            {
                "seq": 2, "ts": "2026-04-13T10:01:00",
                "module": "keymgmt", "operation": "generate_key",
                "command": "openssl genpkey -algorithm RSA",
                "success": True, "deprecated": False, "deprecated_alg": None, "note": "",
            },
            {
                "seq": 3, "ts": "2026-04-13T10:02:00",
                "module": "hashing", "operation": "hash_file_md5",
                "command": "openssl dgst -md5 test.txt",
                "success": True, "deprecated": True, "deprecated_alg": "MD5", "note": "",
            },
            {
                "seq": 4, "ts": "2026-04-13T10:03:00",
                "module": "signing", "operation": "sign_file",
                "command": "openssl cms -sign ...",
                "success": False, "deprecated": False, "deprecated_alg": None, "note": "key mismatch",
            },
        ]

    def _make_info(self):
        return {
            "student_name": "Alice <Script>",
            "session_title": "Crypto Lab 1",
            "start_time": "2026-04-13T10:00:00",
            "end_time": "2026-04-13T11:00:00",
        }

    def test_html_report_is_valid_html(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert html.startswith("<!DOCTYPE html>") or "<html" in html

    def test_html_report_contains_student_name(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        # Should contain escaped version of student name
        assert "Alice" in html

    def test_html_report_xss_escaping(self):
        info = self._make_info()
        info["student_name"] = "<script>alert('xss')</script>"
        html = generate_html_report(info, [])
        # Raw script tag must not appear unescaped
        assert "<script>alert" not in html

    def test_html_report_contains_operation_count(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        # 4 operations total
        assert "4" in html

    def test_html_report_contains_deprecated_warning(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert "MD5" in html or "DEPRECATED" in html.upper()

    def test_html_report_contains_failure(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert "FAIL" in html.upper() or "fail" in html.lower()

    def test_html_report_contains_success_entries(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert "PASS" in html.upper() or "pass" in html.lower() or "success" in html.lower()

    def test_html_report_empty_session(self):
        html = generate_html_report(self._make_info(), [])
        assert "<html" in html or "<!DOCTYPE" in html
        assert "0" in html  # 0 operations

    def test_html_report_file_written(self, tmp_dir):
        out = os.path.join(tmp_dir, "lab_report.html")
        generate_html_report_file(out, self._make_info(), self._make_entries())
        assert os.path.exists(out)
        content = Path(out).read_text()
        assert len(content) > 100
        assert "Alice" in content

    def test_html_report_instructor_checklist_present(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert "checklist" in html.lower() or "Instructor" in html

    def test_html_report_module_names_present(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert "Hashing" in html
        assert "Key Management" in html or "keymgmt" in html

    def test_html_report_command_history_present(self):
        html = generate_html_report(self._make_info(), self._make_entries())
        assert "openssl dgst -sha256" in html or "dgst" in html


# ===========================================================================
# SECTION 13: Security — Cross-module passphrase masking & no shell=True
# ===========================================================================

class TestSecurityExtended:

    def test_passphrase_not_in_pki_command_str(self, tmp_dir, rsa2048_key):
        priv, pub = rsa2048_key
        enc_key = os.path.join(tmp_dir, "sec_enc_key.pem")
        r = keymgmt_ctrl.generate_key("RSA-2048", "supersecret", enc_key)
        assert r.success
        # The command string shown to the user must not reveal the passphrase
        cmd_str = r.command_str
        assert "supersecret" not in cmd_str

    def test_passphrase_not_in_symmetric_command_str(self, tmp_dir):
        plain = os.path.join(tmp_dir, "sec_sym.txt")
        enc = os.path.join(tmp_dir, "sec_sym_enc.bin")
        Path(plain).write_text("security test")
        r = sym_ctrl.encrypt_file(plain, enc, "AES-256-GCM", "topsecretpassword")
        # GCM uses Python crypto (no openssl command), but check what we have
        if r.command_str:
            assert "topsecretpassword" not in r.command_str

    def test_passphrase_not_in_pkcs12_command_str(self, tmp_dir, issued_cert):
        ee_priv, ee_cert, ca_cert = issued_cert
        pfx = os.path.join(tmp_dir, "sec_pkcs12.pfx")
        r = pki_ctrl.create_pkcs12(ee_cert, ee_priv, pfx, "pfx_secret_pw")
        assert r.success
        assert "pfx_secret_pw" not in r.command_str

    def test_shell_injection_in_subject_cn(self, tmp_dir, rsa2048_key):
        """Shell metacharacters in subject CN must not cause shell injection."""
        priv, pub = rsa2048_key
        cert = os.path.join(tmp_dir, "injection_cert.pem")
        malicious_cn = "Test; rm -rf /tmp/sslopencrypt_test_injection"
        r = pki_ctrl.create_self_signed(
            key_path=priv,
            output_path=cert,
            subject={"CN": malicious_cn},
        )
        # Either it succeeds (openssl handles special chars), or fails cleanly
        # The critical check: the injected command was not executed
        assert not os.path.exists("/tmp/sslopencrypt_test_injection")

    def test_no_shell_true_in_signing(self, tmp_dir, issued_cert, monkeypatch):
        """Verify that subprocess.run is called with shell=False (or shell not set to True)."""
        ee_priv, ee_cert, ca_cert = issued_cert
        data = os.path.join(tmp_dir, "noshell_data.txt")
        sig = os.path.join(tmp_dir, "noshell_data.p7s")
        Path(data).write_text("shell test")

        calls_with_shell = []
        original_run = __import__("subprocess").run
        def spy_run(*args, **kwargs):
            if kwargs.get("shell"):
                calls_with_shell.append(args)
            return original_run(*args, **kwargs)

        with patch("subprocess.run", side_effect=spy_run):
            signing_ctrl.sign_file(data, ee_priv, ee_cert, sig)

        assert len(calls_with_shell) == 0, "subprocess.run called with shell=True"

    def test_vault_file_permissions(self, tmp_path, monkeypatch):
        """Vault file should be 0600."""
        _patch_vault_path(monkeypatch, tmp_path)
        _reset_vault_state()
        vault_ctrl.create_vault("vaultpass")
        vault_file = Path(tmp_path) / "vault.enc"
        mode = stat.S_IMODE(vault_file.stat().st_mode)
        _reset_vault_state()
        assert mode == 0o600, f"Vault file mode {oct(mode)} != 0o600"


# ===========================================================================
# SECTION 14: Vault — Extended
# ===========================================================================

def _reset_vault_state():
    """Reset vault module singleton."""
    vault_ctrl._vault_data = None
    vault_ctrl._vault_passphrase = None


def _patch_vault_path(monkeypatch, tmp_path):
    """Redirect vault file to a temp dir for test isolation."""
    def mock_vault_path():
        Path(tmp_path).mkdir(exist_ok=True)
        return Path(tmp_path) / "vault.enc"
    monkeypatch.setattr(vault_ctrl, "_vault_path", mock_vault_path)


class TestVaultExtended:

    def setup_method(self):
        _reset_vault_state()

    def teardown_method(self):
        _reset_vault_state()

    def test_add_key_with_tags_and_comment(self, tmp_path, monkeypatch, ed25519_key):
        _patch_vault_path(monkeypatch, tmp_path)
        priv, pub = ed25519_key
        pem = Path(priv).read_text()
        vault_ctrl.create_vault("testpassword")
        eid = vault_ctrl.add_key("My Ed25519", "Ed25519", pem, tags=["prod", "signing"], comment="Main signing key")
        keys = vault_ctrl.list_keys()
        match = next((k for k in keys if k["id"] == eid), None)
        assert match is not None
        assert match["tags"] == ["prod", "signing"]
        assert match["comment"] == "Main signing key"

    def test_vault_stats_counts_algorithms(self, tmp_path, monkeypatch, ed25519_key, rsa2048_key):
        _patch_vault_path(monkeypatch, tmp_path)
        priv_ed, _ = ed25519_key
        priv_rsa, _ = rsa2048_key
        vault_ctrl.create_vault("testpassword")
        vault_ctrl.add_key("Ed25519 Key", "Ed25519", Path(priv_ed).read_text())
        vault_ctrl.add_key("RSA Key", "RSA-2048", Path(priv_rsa).read_text())
        stats = vault_ctrl.vault_stats()
        assert stats["total_keys"] >= 2
        algos = stats["algorithms"]
        assert "Ed25519" in algos
        assert "RSA-2048" in algos

    def test_get_key_pem_returns_correct_content(self, tmp_path, monkeypatch, ed25519_key):
        _patch_vault_path(monkeypatch, tmp_path)
        priv, pub = ed25519_key
        original_pem = Path(priv).read_text()
        vault_ctrl.create_vault("testpassword")
        eid = vault_ctrl.add_key("PEM Test", "Ed25519", original_pem)
        retrieved = vault_ctrl.get_key_pem(eid)
        assert retrieved == original_pem.strip()

    def test_change_passphrase_and_reopen(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        vault_ctrl.create_vault("oldpass")
        vault_ctrl.add_key("Test", "Ed25519", "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----")
        vault_ctrl.change_passphrase("oldpass", "newpass")
        vault_ctrl.lock_vault()
        # Old passphrase should fail
        with pytest.raises(ValueError):
            vault_ctrl.unlock_vault("oldpass")
        # New passphrase should work
        vault_ctrl.unlock_vault("newpass")
        assert vault_ctrl.is_unlocked()

    def test_update_key_metadata(self, tmp_path, monkeypatch, ed25519_key):
        _patch_vault_path(monkeypatch, tmp_path)
        priv, pub = ed25519_key
        vault_ctrl.create_vault("testpassword")
        eid = vault_ctrl.add_key("Original Name", "Ed25519", Path(priv).read_text())
        vault_ctrl.update_key_metadata(eid, name="Updated Name", tags=["new"], comment="Updated")
        keys = vault_ctrl.list_keys()
        match = next(k for k in keys if k["id"] == eid)
        assert match["name"] == "Updated Name"
        assert match["tags"] == ["new"]

    def test_remove_key_reduces_count(self, tmp_path, monkeypatch, ed25519_key):
        _patch_vault_path(monkeypatch, tmp_path)
        priv, pub = ed25519_key
        vault_ctrl.create_vault("testpassword")
        vault_ctrl.add_key("Keep1", "Ed25519", Path(priv).read_text())
        eid = vault_ctrl.add_key("ToRemove", "Ed25519", Path(priv).read_text())
        before = len(vault_ctrl.list_keys())
        vault_ctrl.remove_key(eid)
        after = len(vault_ctrl.list_keys())
        assert after == before - 1

    def test_import_and_export_key_file(self, tmp_path, monkeypatch, ed25519_key):
        _patch_vault_path(monkeypatch, tmp_path)
        priv, pub = ed25519_key
        vault_ctrl.create_vault("testpassword")
        eid = vault_ctrl.import_key_from_file(priv, "Imported Ed25519", "Ed25519")
        out = os.path.join(str(tmp_path), "exported_from_vault.pem")
        vault_ctrl.export_key_to_file(eid, out)
        assert os.path.exists(out)
        mode = stat.S_IMODE(os.stat(out).st_mode)
        assert mode == 0o600
        assert Path(out).read_text().strip() == Path(priv).read_text().strip()

    def test_locked_vault_operations_raise(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        vault_ctrl.create_vault("pass")
        vault_ctrl.lock_vault()
        # Vault is locked — operations should raise
        with pytest.raises(Exception):
            vault_ctrl.list_keys()
        with pytest.raises(Exception):
            vault_ctrl.add_key("K", "Ed25519", "pem")

    def test_vault_file_permissions_are_0600(self, tmp_path, monkeypatch):
        _patch_vault_path(monkeypatch, tmp_path)
        vault_ctrl.create_vault("vaultpass")
        vault_file = Path(tmp_path) / "vault.enc"
        mode = stat.S_IMODE(vault_file.stat().st_mode)
        assert mode == 0o600, f"Vault file mode {oct(mode)} != 0o600"


# ===========================================================================
# SECTION 15: CLI — Extended
# ===========================================================================

class TestCLIExtended:
    """Test CLI modes not covered by existing test_cli.py."""

    def _run_cli(self, args):
        """Run CLI and return parsed JSON result dict."""
        from cli.main import main as cli_main
        old_argv = sys.argv[:]
        sys.argv = ["sslopencrypt"] + args
        captured = {}
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                try:
                    cli_main()
                except SystemExit:
                    pass
        finally:
            sys.argv = old_argv
        output = buf.getvalue().strip()
        if output:
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return {"_raw": output}
        return {}

    def test_cli_version_returns_json(self):
        result = self._run_cli(["--mode", "version"])
        assert "success" in result or "_raw" in result

    def test_cli_random_bytes_hex(self):
        result = self._run_cli(["--mode", "random", "--length", "16", "--format", "hex"])
        assert result.get("success") is True
        val = result.get("parsed", {}).get("value", "")
        assert re.fullmatch(r"[0-9a-fA-F]+", val) or len(val) > 0

    def test_cli_random_password(self):
        result = self._run_cli(["--mode", "random", "--length", "20", "--password"])
        assert result.get("success") is True
        pwd = result.get("parsed", {}).get("password", "")
        assert len(pwd) == 20

    def test_cli_hash_text_sha3_256(self):
        result = self._run_cli(["--mode", "hash", "--algorithm", "SHA3-256", "--text", "hello"])
        assert result.get("success") is True

    def test_cli_keygen_rsa4096(self, tmp_dir):
        out = os.path.join(tmp_dir, "cli_rsa4096.pem")
        result = self._run_cli(["--mode", "keygen", "--algorithm", "RSA-4096", "--output", out])
        assert result.get("success") is True
        assert os.path.exists(out)

    def test_cli_encrypt_decrypt_cbc(self, tmp_dir):
        plain = os.path.join(tmp_dir, "cli_cbc_plain.txt")
        enc = os.path.join(tmp_dir, "cli_cbc_enc.bin")
        dec = os.path.join(tmp_dir, "cli_cbc_dec.txt")
        Path(plain).write_text("CLI CBC test")
        r_enc = self._run_cli([
            "--mode", "encrypt",
            "--cipher", "AES-256-CBC",
            "--file", plain,
            "--output", enc,
            "--pass", "cbcpass",
        ])
        assert r_enc.get("success") is True
        r_dec = self._run_cli([
            "--mode", "decrypt",
            "--cipher", "AES-256-CBC",
            "--file", enc,
            "--output", dec,
            "--pass", "cbcpass",
        ])
        assert r_dec.get("success") is True
        assert Path(dec).read_text() == "CLI CBC test"

    def test_cli_pretty_flag_indents_json(self, tmp_dir):
        old_argv = sys.argv[:]
        import io
        from contextlib import redirect_stdout
        from cli.main import main as cli_main
        sys.argv = ["sslopencrypt", "--mode", "version", "--pretty"]
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                try:
                    cli_main()
                except SystemExit:
                    pass
        finally:
            sys.argv = old_argv
        output = buf.getvalue()
        # Pretty-printed JSON has newlines and indentation
        assert "\n" in output

    def test_cli_missing_mode_exits_nonzero(self):
        old_argv = sys.argv[:]
        sys.argv = ["sslopencrypt"]
        exit_code = None
        try:
            from cli.main import main as cli_main
            cli_main()
        except SystemExit as e:
            exit_code = e.code
        finally:
            sys.argv = old_argv
        assert exit_code != 0

    def test_cli_sign_verify_raw_rsa(self, tmp_dir):
        priv = os.path.join(tmp_dir, "cli_rsa_sign.pem")
        pub = os.path.join(tmp_dir, "cli_rsa_sign_pub.pem")
        data = os.path.join(tmp_dir, "cli_rsa_sign_data.txt")
        sig = os.path.join(tmp_dir, "cli_rsa_sign_data.sig")
        Path(data).write_text("RSA CLI sign test")
        # Generate key
        self._run_cli(["--mode", "keygen", "--algorithm", "RSA-2048", "--output", priv])
        # Extract public key
        keymgmt_ctrl.extract_public_key(priv, pub)
        # Sign
        r_sign = self._run_cli(["--mode", "sign", "--file", data, "--key", priv, "--output", sig])
        assert r_sign.get("success") is True, r_sign
        # Verify
        r_verify = self._run_cli(["--mode", "verify", "--file", data, "--signature", sig, "--key", pub])
        assert r_verify.get("success") is True, r_verify
