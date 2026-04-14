"""
tests/test_india_dsc.py — Unit tests for the India DSC module new features.

Tests cover:
  - RCAI fingerprint format and non-placeholder content
  - check_certificate_expiry: valid, expiring-soon, expired, missing file
  - check_token_pin_health: no tool present path
  - validate_for_portal: all 4 portals, pass / fail / PAN-check paths
  - esign_build_request: XML structure, stub flag, known ASPs
  - list_supported_portals: completeness
"""

import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from modules.india_dsc.controller import (
    RCAI_SHA256_FINGERPRINT,
    RCAI_SPL_SHA256_FINGERPRINT,
    check_certificate_expiry,
    check_token_pin_health,
    esign_build_request,
    list_supported_portals,
    validate_for_portal,
    ESIGN_ASPS,
    PORTAL_RULES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cert_pem(days_until_expiry: int) -> str:
    """Generate a self-signed certificate expiring in `days_until_expiry` days."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org Pvt Ltd"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Signer ABCDE1234F"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, "ABCDE1234F"),
    ])
    # For negative days_until_expiry (already expired certs) we must ensure
    # not_valid_before < not_valid_after, so push not_valid_before further back.
    valid_from = now - timedelta(days=max(10, abs(days_until_expiry) + 2))
    valid_until = now + timedelta(days=days_until_expiry)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_until)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _make_individual_cert_pem(days: int = 365, pan: str = "") -> str:
    """Self-signed cert without an Organisation attribute (individual DSC)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=timezone.utc)
    attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"Test Individual {pan or 'ABCDE1234F'}"),
    ]
    if pan:
        attrs.append(x509.NameAttribute(NameOID.SERIAL_NUMBER, pan))
    subject = x509.Name(attrs)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# 1. RCAI fingerprint
# ---------------------------------------------------------------------------

class TestRCAIFingerprint:
    def test_primary_not_placeholder(self):
        """The primary RCAI fingerprint must not contain the fabricated pattern."""
        assert "1A:B2:C3:D4" not in RCAI_SHA256_FINGERPRINT

    def test_primary_format(self):
        """SHA-256 fingerprint = 32 bytes = 64 hex chars = 31 colons."""
        parts = RCAI_SHA256_FINGERPRINT.split(":")
        assert len(parts) == 32, f"Expected 32 groups, got {len(parts)}"
        for p in parts:
            assert len(p) == 2, f"Each group must be 2 hex chars, got '{p}'"
            int(p, 16)  # must be valid hex

    def test_spl_format(self):
        parts = RCAI_SPL_SHA256_FINGERPRINT.split(":")
        assert len(parts) == 32
        for p in parts:
            assert len(p) == 2
            int(p, 16)

    def test_primary_known_value(self):
        """Verify the CCA India 2022 fingerprint matches the downloaded cert."""
        assert RCAI_SHA256_FINGERPRINT == (
            "9A:3F:D3:17:67:98:E8:42:DD:CB:12:C2:62:F1:1C:FA:"
            "CC:A7:0A:8B:84:C6:EA:6F:DA:30:84:2A:95:A9:4C:D8"
        )


# ---------------------------------------------------------------------------
# 2. Certificate expiry check
# ---------------------------------------------------------------------------

class TestCertificateExpiry:
    def test_valid_cert(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = check_certificate_expiry(str(cert_file))
        assert r.success
        assert r.parsed["status"] == "valid"
        assert r.parsed["alert_level"] == "green"
        assert r.parsed["days_remaining"] > 30

    def test_expiring_soon_cert(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=15)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = check_certificate_expiry(str(cert_file))
        assert r.success
        assert r.parsed["status"] == "expiring_soon"
        assert r.parsed["alert_level"] == "amber"
        assert 1 <= r.parsed["days_remaining"] <= 30

    def test_expired_cert(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=-5)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = check_certificate_expiry(str(cert_file))
        assert r.success
        assert r.parsed["status"] == "expired"
        assert r.parsed["alert_level"] == "red"
        assert r.parsed["days_remaining"] < 0

    def test_missing_file(self):
        r = check_certificate_expiry("/nonexistent/path/cert.pem")
        assert not r.success

    def test_parsed_keys_present(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=100)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = check_certificate_expiry(str(cert_file))
        for key in ("subject", "issuer", "not_before", "not_after",
                    "days_remaining", "status", "alert_level"):
            assert key in r.parsed, f"Missing key: {key}"

    def test_stdout_contains_status(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=200)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = check_certificate_expiry(str(cert_file))
        assert "VALID" in r.stdout.upper()


# ---------------------------------------------------------------------------
# 3. Token PIN health — no tool present path
# ---------------------------------------------------------------------------

class TestTokenPinHealth:
    def test_no_pkcs11_tool(self, monkeypatch):
        """When pkcs11-tool is absent, return failure with clear message."""
        import modules.india_dsc.controller as ctrl
        monkeypatch.setattr(ctrl, "_pkcs11_tool", lambda: None)
        r = check_token_pin_health("/nonexistent/lib.so")
        assert not r.success
        assert "pkcs11-tool" in r.stderr.lower()


# ---------------------------------------------------------------------------
# 4. Portal workflow validators
# ---------------------------------------------------------------------------

class TestPortalValidator:
    # --- MCA21 ---
    def test_mca21_org_cert_passes(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)  # has org in subject
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "MCA21")
        assert r.parsed["ready_to_sign"]
        assert r.parsed["issues"] == []

    def test_mca21_individual_cert_fails(self, tmp_path):
        pem = _make_individual_cert_pem(days=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "MCA21")
        assert not r.parsed["ready_to_sign"]
        assert any("organisation" in i.lower() for i in r.parsed["issues"])

    # --- IT e-filing ---
    def test_it_efiling_pan_match_passes(self, tmp_path):
        pan = "ABCDE1234F"
        pem = _make_individual_cert_pem(days=365, pan=pan)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "IT_EFILING", pan=pan)
        # PAN check should pass; cert type is individual so no org-type failure
        pan_check = next(c for c in r.parsed["checks"] if c["check"] == "PAN match")
        assert pan_check["result"] == "pass"

    def test_it_efiling_pan_mismatch_fails(self, tmp_path):
        pem = _make_individual_cert_pem(days=365, pan="ABCDE1234F")
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "IT_EFILING", pan="ZZZZZ9999Z")
        pan_check = next(c for c in r.parsed["checks"] if c["check"] == "PAN match")
        assert pan_check["result"] == "fail"
        assert not r.parsed["ready_to_sign"]

    def test_it_efiling_no_pan_warns(self, tmp_path):
        pem = _make_individual_cert_pem(days=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "IT_EFILING")
        pan_check = next(c for c in r.parsed["checks"] if c["check"] == "PAN match")
        assert pan_check["result"] == "warn"

    # --- GST ---
    def test_gst_any_cert_passes_with_valid_cert(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "GST")
        assert r.parsed["ready_to_sign"]

    # --- GeM ---
    def test_gem_timestamp_warning_present(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "GeM")
        ts_check = next(
            (c for c in r.parsed["checks"] if c["check"] == "Timestamp requirement"), None
        )
        assert ts_check is not None
        assert ts_check["result"] == "warn"

    def test_gem_alias_normalisation(self, tmp_path):
        """'GEM' and 'CPPP' should resolve to the GeM portal."""
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r1 = validate_for_portal(str(cert_file), "GEM")
        r2 = validate_for_portal(str(cert_file), "CPPP")
        assert r1.parsed["portal_name"] == r2.parsed["portal_name"]

    # --- General ---
    def test_unknown_portal_returns_error(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "UNKNOWN_PORTAL")
        assert not r.success

    def test_expired_cert_fails_all_portals(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=-1)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        for portal in ["MCA21", "IT_EFILING", "GST", "GeM"]:
            r = validate_for_portal(str(cert_file), portal)
            validity_check = next(c for c in r.parsed["checks"] if c["check"] == "Certificate validity")
            assert validity_check["result"] == "fail", f"Expected fail for expired cert on {portal}"

    def test_missing_cert_file(self):
        r = validate_for_portal("/no/such/file.pem", "MCA21")
        assert not r.success

    def test_parsed_keys_present(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        r = validate_for_portal(str(cert_file), "MCA21")
        for key in ("portal_name", "checks", "ready_to_sign", "issues", "notes", "format"):
            assert key in r.parsed

    def test_notes_non_empty(self, tmp_path):
        pem = _make_cert_pem(days_until_expiry=365)
        cert_file = tmp_path / "cert.pem"
        cert_file.write_text(pem)

        for portal in PORTAL_RULES:
            r = validate_for_portal(str(cert_file), portal)
            assert r.parsed["notes"], f"Portal {portal} has no workflow notes"


# ---------------------------------------------------------------------------
# 5. list_supported_portals
# ---------------------------------------------------------------------------

class TestListSupportedPortals:
    def test_returns_four_portals(self):
        portals = list_supported_portals()
        assert len(portals) == 4

    def test_all_required_keys(self):
        for p in list_supported_portals():
            for key in ("key", "full_name", "url", "format", "cert_type"):
                assert key in p, f"Portal {p.get('key')} missing key '{key}'"

    def test_known_portals_present(self):
        keys = {p["key"] for p in list_supported_portals()}
        assert {"MCA21", "IT_EFILING", "GST", "GeM"}.issubset(keys)


# ---------------------------------------------------------------------------
# 6. eSign API stub
# ---------------------------------------------------------------------------

class TestESignBuildRequest:
    def test_returns_success(self):
        r = esign_build_request("a" * 64)
        assert r.success

    def test_xml_in_parsed(self):
        r = esign_build_request("b" * 64)
        assert "xml" in r.parsed
        assert r.parsed["xml"].startswith("<?xml")

    def test_stub_flag(self):
        r = esign_build_request("c" * 64)
        assert r.parsed.get("stub") is True

    def test_xml_contains_input_hash(self):
        doc_hash = "d" * 64
        r = esign_build_request(doc_hash)
        assert doc_hash in r.parsed["xml"]

    def test_xml_contains_asp_id(self):
        r = esign_build_request("e" * 64, asp_id="MY_ASP_123")
        assert "MY_ASP_123" in r.parsed["xml"]

    def test_xml_contains_txn_id(self):
        r = esign_build_request("f" * 64, asp_txn_id="TXN-001")
        assert "TXN-001" in r.parsed["xml"]

    def test_custom_txn_auto_generated_when_blank(self):
        r = esign_build_request("g" * 64)
        # auto-generated UUID must be in the XML
        txn = r.parsed["asp_txn_id"]
        assert txn in r.parsed["xml"]

    def test_hash_algorithm_in_xml(self):
        r = esign_build_request("h" * 64, hash_algorithm="SHA512")
        assert "SHA512" in r.parsed["xml"]

    def test_asps_returned(self):
        r = esign_build_request("i" * 64)
        asps = r.parsed.get("asps", {})
        for key in ("eMudhra", "NSDL", "CDAC"):
            assert key in asps

    def test_asps_have_gateway_url(self):
        for key, asp in ESIGN_ASPS.items():
            assert "gateway_url" in asp, f"{key} missing gateway_url"
            assert asp["gateway_url"].startswith("https://")

    def test_stdout_contains_stub_notice(self):
        r = esign_build_request("j" * 64)
        assert "STUB" in r.stdout.upper() or "stub" in r.stdout.lower()

    def test_xml_root_element_is_esign(self):
        import xml.etree.ElementTree as ET
        r = esign_build_request("k" * 64)
        root = ET.fromstring(r.parsed["xml"].split("\n", 1)[1])  # skip XML declaration
        assert root.tag == "Esign"

    def test_xml_has_docs_element(self):
        import xml.etree.ElementTree as ET
        r = esign_build_request("l" * 64)
        root = ET.fromstring(r.parsed["xml"].split("\n", 1)[1])
        docs = root.find("Docs")
        assert docs is not None
        input_hash = docs.find("InputHash")
        assert input_hash is not None
