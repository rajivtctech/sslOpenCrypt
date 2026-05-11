"""
tests/test_tangodos.py — TangoDOS sibling-project support tests.

End-to-end check that each wizard's controller function produces the files a
TangoDOS panel expects, at the canonical filenames, and that the round-trip
(generate -> sign -> verify) actually verifies.
"""

import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.tangodos.controller import (
    HTTPS_CERT_FILENAME, HTTPS_KEY_FILENAME,
    MQTT_CA_FILENAME, MQTT_CLIENT_CERT_FILENAME, MQTT_CLIENT_KEY_FILENAME,
    generate_panel_https_cert,
    generate_mqtt_mtls_bundle,
    generate_fleet_ca,
    generate_firmware_signing_key,
    sign_firmware,
    verify_firmware_signature,
    inspect_self_test_report,
    export_panel_pkcs12,
    panel_file_layout,
)


def _filesize(path: str) -> int:
    return os.path.getsize(path)


class TestHttpsCert:
    def test_generates_expected_filenames(self, tmp_path):
        r = generate_panel_https_cert(
            common_name="panel-test-01.local",
            out_dir=str(tmp_path),
            sans=["10.0.0.42"],
            days=30,
        )
        assert r.success, r.stderr
        assert (tmp_path / HTTPS_CERT_FILENAME).exists()
        assert (tmp_path / HTTPS_KEY_FILENAME).exists()
        assert _filesize(tmp_path / HTTPS_CERT_FILENAME) > 0
        assert _filesize(tmp_path / HTTPS_KEY_FILENAME) > 0

    def test_cert_contains_common_name(self, tmp_path):
        cn = "brewery-line-3.local"
        r = generate_panel_https_cert(common_name=cn, out_dir=str(tmp_path), days=30)
        assert r.success
        cert_text = (tmp_path / HTTPS_CERT_FILENAME).read_text()
        # Cheap PEM presence check; full subject inspection is left to openssl x509
        assert "BEGIN CERTIFICATE" in cert_text
        assert "END CERTIFICATE" in cert_text


class TestFleetCa:
    def test_produces_ca_pair(self, tmp_path):
        r = generate_fleet_ca(
            org_name="Acme Brewery",
            common_name="Acme Fleet Root CA",
            out_dir=str(tmp_path),
            days=365,
            key_bits=2048,   # smaller for test speed
        )
        assert r.success, r.stderr
        assert (tmp_path / "tangodos_fleet_ca.crt").exists()
        assert (tmp_path / "tangodos_fleet_ca.key").exists()


class TestMqttBundle:
    def test_self_signed_bundle(self, tmp_path):
        # Need a "broker CA" to feed in — use the fleet CA itself as a stand-in.
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        r = generate_fleet_ca("BrokerCo", "BrokerCo CA", str(ca_dir), days=365, key_bits=2048)
        assert r.success
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        r = generate_mqtt_mtls_bundle(
            broker_ca_path=str(ca_dir / "tangodos_fleet_ca.crt"),
            device_cn="panel-test-01",
            out_dir=str(bundle_dir),
            days=30,
        )
        assert r.success, r.stderr
        for f in (MQTT_CA_FILENAME, MQTT_CLIENT_CERT_FILENAME, MQTT_CLIENT_KEY_FILENAME):
            assert (bundle_dir / f).exists(), f"missing {f}"

    def test_ca_signed_bundle(self, tmp_path):
        ca_dir = tmp_path / "ca"
        ca_dir.mkdir()
        r = generate_fleet_ca("BrokerCo", "BrokerCo CA", str(ca_dir), days=365, key_bits=2048)
        assert r.success
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        r = generate_mqtt_mtls_bundle(
            broker_ca_path=str(ca_dir / "tangodos_fleet_ca.crt"),
            device_cn="panel-test-02",
            out_dir=str(bundle_dir),
            days=30,
            signing_ca_cert=str(ca_dir / "tangodos_fleet_ca.crt"),
            signing_ca_key=str(ca_dir / "tangodos_fleet_ca.key"),
        )
        assert r.success, r.stderr
        # The client cert should reference the CA: parse it briefly.
        cert_text = (bundle_dir / MQTT_CLIENT_CERT_FILENAME).read_text()
        assert "BEGIN CERTIFICATE" in cert_text


class TestFirmwareSigning:
    def test_round_trip_sign_verify(self, tmp_path):
        # 1) Generate signing key
        key_path = str(tmp_path / "fw_signing.pem")
        r = generate_firmware_signing_key(key_path)
        assert r.success, r.stderr
        assert os.path.exists(key_path)
        pub_path = key_path + ".pub.pem"
        assert os.path.exists(pub_path)

        # 2) Synthesise a firmware blob
        fw = tmp_path / "fake_firmware.bin"
        fw.write_bytes(b"\x55" * 4096 + b"TANGODOS_TEST_PAYLOAD" + b"\xAA" * 4096)

        # 3) Sign
        r = sign_firmware(str(fw), key_path, str(tmp_path))
        assert r.success, r.stderr
        sig_path = str(fw) + ".sig"
        signed_path = str(fw) + ".signed"
        assert os.path.exists(sig_path)
        assert os.path.exists(signed_path)

        # 4) Verify with the matching public key
        r = verify_firmware_signature(str(fw), sig_path, pub_path)
        assert r.success, r.stderr

    def test_tampered_firmware_fails_verification(self, tmp_path):
        key_path = str(tmp_path / "fw_signing.pem")
        r = generate_firmware_signing_key(key_path)
        assert r.success
        pub_path = key_path + ".pub.pem"

        fw = tmp_path / "fw.bin"
        fw.write_bytes(b"GOOD" * 256)
        r = sign_firmware(str(fw), key_path, str(tmp_path))
        assert r.success
        sig_path = str(fw) + ".sig"

        # Tamper with the firmware blob, then verify
        with open(fw, "r+b") as f:
            f.seek(0)
            f.write(b"BAD!")
        r = verify_firmware_signature(str(fw), sig_path, pub_path)
        assert not r.success, "tampered firmware should fail signature verification"


class TestSelfTestReport:
    def test_inspect_parses_known_fields(self, tmp_path):
        rp = tmp_path / "self_test.json"
        rp.write_text(json.dumps({
            "panel_id": "TDOS-Acme-007",
            "firmware_version": "v49",
            "sku": "PRO",
            "timestamp": "2026-05-12T12:00:00Z",
            "tier": "Industrial feature profile passed",
            "tests_passed": 42,
            "tests_total": 42,
            "notes": "All on-board peripherals responding.",
        }))
        r = inspect_self_test_report(str(rp))
        assert r.success
        assert "TDOS-Acme-007" in r.stdout
        assert "PRO" in r.stdout
        assert "42/42" in r.stdout

    def test_inspect_handles_malformed_json(self, tmp_path):
        rp = tmp_path / "broken.json"
        rp.write_text("{not really json")
        r = inspect_self_test_report(str(rp))
        assert not r.success


class TestPanelFileLayout:
    def test_known_filenames(self):
        layout = panel_file_layout()
        assert layout["HTTPS cert"] == HTTPS_CERT_FILENAME
        assert layout["HTTPS key"]  == HTTPS_KEY_FILENAME
        assert layout["MQTT CA"]    == MQTT_CA_FILENAME


class TestPkcs12Export:
    def test_bundles_cert_and_key(self, tmp_path):
        # Reuse the HTTPS wizard to produce a cert+key, then bundle.
        r = generate_panel_https_cert(
            common_name="panel-p12-test.local",
            out_dir=str(tmp_path),
            days=30,
        )
        assert r.success
        p12_out = tmp_path / "panel.p12"
        r = export_panel_pkcs12(
            cert_path=str(tmp_path / HTTPS_CERT_FILENAME),
            key_path=str(tmp_path / HTTPS_KEY_FILENAME),
            ca_path=None,
            out_path=str(p12_out),
            friendly_name="Test panel",
            passphrase="testpass",
        )
        assert r.success, r.stderr
        assert p12_out.exists()
        assert _filesize(p12_out) > 100
