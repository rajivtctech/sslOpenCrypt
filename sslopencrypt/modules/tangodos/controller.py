"""
modules/tangodos/controller.py — TangoDOS sibling-project support.

TangoDOS is a PLC-like automation OS for the Raspberry Pi Pico 2 W (Base SKU)
and Pimoroni Pico Plus 2 W (PRO SKU). It is a separate, proprietary project;
sslOpenCrypt is the canonical host-side companion for the cryptographic
material a TangoDOS panel needs:

  * per-device HTTPS server certificate (LittleFS: /HTTP_CRT.PEM + /HTTP_KEY.PEM)
  * MQTT mutual-TLS client bundle  (/MQTT_CA.PEM, /MQTT_CLIENT_CRT.PEM, /MQTT_CLIENT_KEY.PEM)
  * a small in-house CA for a fleet of panels
  * EC P-256 firmware signing (TangoDOS verifies the detached .sig on boot)
  * verification of TangoDOS "self-test reports" (signed JSON emitted by the panel)
  * a TLS inspector for a running panel
  * PKCS#12 export bundling a panel's cert+key for one-shot upload

The boundary is files and CLI invocations only — no shared compiled code.
This keeps the GPL-v3 license of sslOpenCrypt clear of TangoDOS's proprietary
firmware.
"""

import json
import os
import shutil
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult
from core.tempfile_manager import secure_temp_file


# ---------------------------------------------------------------------------
# Filename conventions — these match TangoDOS's LittleFS expectations.
# A panel reads cert/key from these exact paths on boot.
# ---------------------------------------------------------------------------

HTTPS_CERT_FILENAME       = "HTTP_CRT.PEM"
HTTPS_KEY_FILENAME        = "HTTP_KEY.PEM"
MQTT_CA_FILENAME          = "MQTT_CA.PEM"
MQTT_CLIENT_CERT_FILENAME = "MQTT_CLIENT_CRT.PEM"
MQTT_CLIENT_KEY_FILENAME  = "MQTT_CLIENT_KEY.PEM"

# Default validity windows (days). Customer can override per call.
DEFAULT_PANEL_CERT_DAYS = 825    # CA/B Forum max for end-entity certs
DEFAULT_FLEET_CA_DAYS   = 3650   # 10 years for a fleet root CA

# EC curve used for TangoDOS firmware signing. Matches the README claim of
# "EC P-256 key generation and .bin.signed verification for Pi Pico 2W (RP2350)".
FIRMWARE_SIGNING_CURVE = "prime256v1"


def _bundle_result(results: list[ExecutionResult], parsed: dict | None = None) -> ExecutionResult:
    """Fold a sequence of openssl calls into one ExecutionResult for the console."""
    if not results:
        return ExecutionResult([], "", "", "no operation performed", {}, False, -1)
    final = results[-1]
    final.command_str = "\n".join(r.command_str for r in results)
    if parsed:
        final.parsed.update(parsed)
    return final


# ---------------------------------------------------------------------------
# 1) Per-panel HTTPS server certificate
# ---------------------------------------------------------------------------

def generate_panel_https_cert(
    common_name: str,
    out_dir: str,
    sans: list[str] | None = None,
    days: int = DEFAULT_PANEL_CERT_DAYS,
    key_curve: str = "prime256v1",
    organisation: str = "TangoDOS Panel",
) -> ExecutionResult:
    """
    Produce a self-signed HTTPS server cert + key pair for a single TangoDOS
    panel. Output files are named exactly as the panel firmware expects
    (HTTP_CRT.PEM + HTTP_KEY.PEM) so the operator can drag-and-drop them onto
    the dashboard's file uploader.

    common_name : the panel's hostname or IP (e.g. "panel-brewery-01.local")
    sans        : additional DNS names / IPs (e.g. ["10.0.0.42"])
    """
    out_dir = os.path.expanduser(out_dir)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    cert_path = os.path.join(out_dir, HTTPS_CERT_FILENAME)
    key_path  = os.path.join(out_dir, HTTPS_KEY_FILENAME)

    san_entries = [f"DNS:{common_name}"]
    for s in (sans or []):
        s = s.strip()
        if not s:
            continue
        # Crude IPv4 / DNS classifier — good enough for a wizard.
        if all(p.isdigit() for p in s.split(".")) and s.count(".") == 3:
            san_entries.append(f"IP:{s}")
        else:
            san_entries.append(f"DNS:{s}")
    san_csv = ",".join(san_entries)

    results: list[ExecutionResult] = []

    # 1. Generate EC key (P-256 by default — small, fast on RP2350 BearSSL).
    with secure_temp_file(suffix=".pem", prefix="tdos_https_param_") as param:
        r = run_openssl(["ecparam", "-name", key_curve, "-genkey", "-noout", "-out", param.path])
        results.append(r)
        if not r.success:
            return _bundle_result(results)
        # Convert to PKCS#8 unencrypted (TangoDOS firmware expects unencrypted PEM)
        r = run_openssl(["pkcs8", "-topk8", "-in", param.path, "-out", key_path, "-nocrypt"])
        results.append(r)
        if not r.success:
            return _bundle_result(results)

    # 2. Build a one-shot openssl.cnf so SANs land in the cert.
    cnf_lines = [
        "[req]",
        "distinguished_name = dn",
        "x509_extensions = v3_req",
        "prompt = no",
        "[dn]",
        f"CN = {common_name}",
        f"O  = {organisation}",
        "[v3_req]",
        "basicConstraints = critical, CA:FALSE",
        "keyUsage = critical, digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth",
        f"subjectAltName = {san_csv}",
    ]
    with secure_temp_file(suffix=".cnf", prefix="tdos_https_cnf_") as cnf:
        Path(cnf.path).write_text("\n".join(cnf_lines))
        r = run_openssl([
            "req", "-new", "-x509",
            "-key", key_path,
            "-days", str(days),
            "-out", cert_path,
            "-config", cnf.path,
        ])
        results.append(r)

    parsed = {
        "cert_path": cert_path,
        "key_path":  key_path,
        "common_name": common_name,
        "sans": san_entries,
        "days": days,
        "curve": key_curve,
    }
    final = _bundle_result(results, parsed)
    log_operation(
        module="tangodos",
        operation=f"generate_panel_https_cert:{common_name}",
        command_str=final.command_str,
        success=final.success,
    )
    return final


# ---------------------------------------------------------------------------
# 2) MQTT mutual-TLS client bundle
# ---------------------------------------------------------------------------

def generate_mqtt_mtls_bundle(
    broker_ca_path: str,
    device_cn: str,
    out_dir: str,
    days: int = DEFAULT_PANEL_CERT_DAYS,
    key_curve: str = "prime256v1",
    signing_ca_cert: str | None = None,
    signing_ca_key: str | None = None,
) -> ExecutionResult:
    """
    Produce the three files a TangoDOS panel needs for mTLS to an MQTT broker:

      MQTT_CA.PEM           — broker's CA (copied in, used as truststore)
      MQTT_CLIENT_CRT.PEM   — this panel's client cert
      MQTT_CLIENT_KEY.PEM   — this panel's client key (unencrypted PEM)

    If signing_ca_cert + signing_ca_key are provided, the client cert is signed
    by that CA (typical: your fleet CA from generate_fleet_ca). Otherwise the
    client cert is self-signed — fine for "broker accepts client_id only" or
    for laboratory deployments, but not for real mTLS.
    """
    out_dir = os.path.expanduser(out_dir)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    ca_out     = os.path.join(out_dir, MQTT_CA_FILENAME)
    cert_out   = os.path.join(out_dir, MQTT_CLIENT_CERT_FILENAME)
    key_out    = os.path.join(out_dir, MQTT_CLIENT_KEY_FILENAME)

    results: list[ExecutionResult] = []

    # Truststore: just copy the broker CA into the bundle dir.
    try:
        shutil.copyfile(os.path.expanduser(broker_ca_path), ca_out)
    except OSError as e:
        return ExecutionResult([], "", "", f"failed to copy broker CA: {e}", {}, False, -1)

    # Generate client EC key.
    with secure_temp_file(suffix=".pem", prefix="tdos_mqtt_param_") as param:
        r = run_openssl(["ecparam", "-name", key_curve, "-genkey", "-noout", "-out", param.path])
        results.append(r)
        if not r.success:
            return _bundle_result(results)
        r = run_openssl(["pkcs8", "-topk8", "-in", param.path, "-out", key_out, "-nocrypt"])
        results.append(r)
        if not r.success:
            return _bundle_result(results)

    cnf_lines = [
        "[req]",
        "distinguished_name = dn",
        "prompt = no",
        "req_extensions = v3_req",
        "[dn]",
        f"CN = {device_cn}",
        "O  = TangoDOS MQTT Client",
        "[v3_req]",
        "basicConstraints = critical, CA:FALSE",
        "keyUsage = critical, digitalSignature",
        "extendedKeyUsage = clientAuth",
    ]
    with secure_temp_file(suffix=".cnf", prefix="tdos_mqtt_cnf_") as cnf, \
         secure_temp_file(suffix=".csr", prefix="tdos_mqtt_csr_") as csr:
        Path(cnf.path).write_text("\n".join(cnf_lines))
        r = run_openssl([
            "req", "-new", "-key", key_out,
            "-out", csr.path, "-config", cnf.path,
        ])
        results.append(r)
        if not r.success:
            return _bundle_result(results)

        if signing_ca_cert and signing_ca_key:
            # CA-signed client cert.
            r = run_openssl([
                "x509", "-req",
                "-in", csr.path,
                "-CA", os.path.expanduser(signing_ca_cert),
                "-CAkey", os.path.expanduser(signing_ca_key),
                "-CAcreateserial",
                "-days", str(days),
                "-out", cert_out,
                "-extfile", cnf.path,
                "-extensions", "v3_req",
            ])
        else:
            # Self-signed — handy for testing.
            r = run_openssl([
                "x509", "-req",
                "-in", csr.path,
                "-signkey", key_out,
                "-days", str(days),
                "-out", cert_out,
                "-extfile", cnf.path,
                "-extensions", "v3_req",
            ])
        results.append(r)

    parsed = {
        "ca_path":     ca_out,
        "cert_path":   cert_out,
        "key_path":    key_out,
        "device_cn":   device_cn,
        "ca_signed":   bool(signing_ca_cert and signing_ca_key),
        "days":        days,
    }
    final = _bundle_result(results, parsed)
    log_operation("tangodos", f"generate_mqtt_mtls_bundle:{device_cn}", final.command_str, final.success)
    return final


# ---------------------------------------------------------------------------
# 3) Fleet CA — for shops running many TangoDOS panels
# ---------------------------------------------------------------------------

def generate_fleet_ca(
    org_name: str,
    common_name: str,
    out_dir: str,
    days: int = DEFAULT_FLEET_CA_DAYS,
    key_bits: int = 4096,
) -> ExecutionResult:
    """
    Produce a self-signed root CA the operator can use to sign per-panel
    HTTPS / MQTT certs. RSA-4096 by default — operators tend to expect that
    for a long-lived root.

    Outputs:
      tangodos_fleet_ca.crt   (PEM cert, distribute to brokers' cafile)
      tangodos_fleet_ca.key   (PEM key,  guard this file)
    """
    out_dir = os.path.expanduser(out_dir)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    cert_out = os.path.join(out_dir, "tangodos_fleet_ca.crt")
    key_out  = os.path.join(out_dir, "tangodos_fleet_ca.key")

    results: list[ExecutionResult] = []
    r = run_openssl([
        "genpkey", "-algorithm", "RSA",
        "-pkeyopt", f"rsa_keygen_bits:{key_bits}",
        "-out", key_out,
    ])
    results.append(r)
    if not r.success:
        return _bundle_result(results)

    cnf_lines = [
        "[req]",
        "distinguished_name = dn",
        "x509_extensions = v3_ca",
        "prompt = no",
        "[dn]",
        f"CN = {common_name}",
        f"O  = {org_name}",
        "[v3_ca]",
        "basicConstraints = critical, CA:TRUE",
        "keyUsage = critical, keyCertSign, cRLSign",
        "subjectKeyIdentifier = hash",
    ]
    with secure_temp_file(suffix=".cnf", prefix="tdos_ca_cnf_") as cnf:
        Path(cnf.path).write_text("\n".join(cnf_lines))
        r = run_openssl([
            "req", "-new", "-x509",
            "-key", key_out,
            "-days", str(days),
            "-out", cert_out,
            "-config", cnf.path,
        ])
        results.append(r)

    parsed = {
        "ca_cert_path": cert_out,
        "ca_key_path":  key_out,
        "org_name":     org_name,
        "common_name":  common_name,
        "days":         days,
    }
    final = _bundle_result(results, parsed)
    log_operation("tangodos", f"generate_fleet_ca:{org_name}", final.command_str, final.success)
    return final


# ---------------------------------------------------------------------------
# 4) Firmware signing — EC P-256, detached signature
# ---------------------------------------------------------------------------

def generate_firmware_signing_key(out_path: str) -> ExecutionResult:
    """Produce an EC P-256 keypair for TangoDOS firmware signing.

    Outputs:  <out_path>          — private key (PEM, PKCS#8 unencrypted)
              <out_path>.pub.pem  — public key  (distribute to the panel's verify chain)
    """
    out_path = os.path.expanduser(out_path)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    pub_out = out_path + ".pub.pem"

    results: list[ExecutionResult] = []
    with secure_temp_file(suffix=".pem", prefix="tdos_fw_param_") as param:
        r = run_openssl(["ecparam", "-name", FIRMWARE_SIGNING_CURVE, "-genkey", "-noout", "-out", param.path])
        results.append(r)
        if not r.success:
            return _bundle_result(results)
        r = run_openssl(["pkcs8", "-topk8", "-in", param.path, "-out", out_path, "-nocrypt"])
        results.append(r)
        if not r.success:
            return _bundle_result(results)

    r = run_openssl(["pkey", "-in", out_path, "-pubout", "-out", pub_out])
    results.append(r)
    parsed = {"private_key_path": out_path, "public_key_path": pub_out, "curve": FIRMWARE_SIGNING_CURVE}
    final = _bundle_result(results, parsed)
    log_operation("tangodos", "generate_firmware_signing_key", final.command_str, final.success)
    return final


def sign_firmware(firmware_path: str, signing_key_path: str, out_dir: str | None = None) -> ExecutionResult:
    """Produce a detached ECDSA signature over the firmware blob.

    Inputs:  firmware_path     — .bin or .uf2 (any bytes)
             signing_key_path  — EC P-256 PEM produced by generate_firmware_signing_key

    Outputs (in out_dir, defaults to alongside the firmware):
             <firmware>.sig        — DER-encoded ECDSA signature
             <firmware>.bin.signed — convenience: firmware || sig  (panel can re-split)
    """
    firmware_path = os.path.expanduser(firmware_path)
    signing_key_path = os.path.expanduser(signing_key_path)
    if not os.path.isfile(firmware_path):
        return ExecutionResult([], "", "", f"firmware not found: {firmware_path}", {}, False, -1)
    if out_dir is None:
        out_dir = os.path.dirname(firmware_path) or "."
    out_dir = os.path.expanduser(out_dir)
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    base = os.path.basename(firmware_path)
    sig_out    = os.path.join(out_dir, base + ".sig")
    signed_out = os.path.join(out_dir, base + ".signed")

    r = run_openssl([
        "dgst", "-sha256",
        "-sign", signing_key_path,
        "-out", sig_out,
        firmware_path,
    ])

    if r.success:
        try:
            with open(firmware_path, "rb") as fw, open(sig_out, "rb") as sig, open(signed_out, "wb") as out:
                out.write(fw.read())
                out.write(sig.read())
            r.parsed["signed_path"] = signed_out
        except OSError as e:
            r.success = False
            r.stderr = f"failed to write signed blob: {e}"
    r.parsed.update({
        "firmware_path": firmware_path,
        "signature_path": sig_out,
        "signing_key_path": signing_key_path,
    })
    log_operation("tangodos", f"sign_firmware:{base}", r.command_str, r.success)
    return r


def verify_firmware_signature(firmware_path: str, signature_path: str, public_key_path: str) -> ExecutionResult:
    """Verify a detached firmware signature against a known public key.

    Mirrors what the panel itself does on first boot of a new firmware image.
    """
    firmware_path = os.path.expanduser(firmware_path)
    signature_path = os.path.expanduser(signature_path)
    public_key_path = os.path.expanduser(public_key_path)
    r = run_openssl([
        "dgst", "-sha256",
        "-verify", public_key_path,
        "-signature", signature_path,
        firmware_path,
    ])
    log_operation("tangodos", f"verify_firmware_signature:{os.path.basename(firmware_path)}", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# 5) Self-test report verification
# ---------------------------------------------------------------------------

def verify_self_test_report(report_path: str, signature_path: str, public_key_path: str) -> ExecutionResult:
    """Verify the detached signature on a TangoDOS self-test report.

    A self-test report is a JSON document the panel emits via the dashboard
    ('Diagnostics → Export self-test report'). The signature is produced on
    the panel using its firmware-signing key. Verification confirms the
    report was produced by a panel whose firmware was signed by the
    matching private key — useful for compliance evidence.
    """
    return verify_firmware_signature(report_path, signature_path, public_key_path)


def inspect_self_test_report(report_path: str) -> ExecutionResult:
    """Cheaply parse and summarise a TangoDOS self-test report (no crypto)."""
    report_path = os.path.expanduser(report_path)
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return ExecutionResult(
            command=["(local parse)"], command_str=f"(local parse) {report_path}",
            stdout="", stderr=f"failed to read report: {e}",
            parsed={}, success=False, exit_code=-1,
        )

    summary_lines = [
        f"Panel:       {data.get('panel_id', '(unknown)')}",
        f"Firmware:    {data.get('firmware_version', '(unknown)')}",
        f"SKU:         {data.get('sku', '(unknown)')}",
        f"Generated:   {data.get('timestamp', '(unknown)')}",
        f"Tier:        {data.get('tier', '(unknown)')}",
        f"Passed:      {data.get('tests_passed', '?')}/{data.get('tests_total', '?')}",
    ]
    if "notes" in data:
        summary_lines.append("Notes:")
        for line in str(data["notes"]).splitlines():
            summary_lines.append(f"  {line}")

    return ExecutionResult(
        command=["(local parse)"], command_str=f"(local parse) {report_path}",
        stdout="\n".join(summary_lines), stderr="",
        parsed=data, success=True, exit_code=0,
    )


# ---------------------------------------------------------------------------
# 6) TLS inspector — point at a running panel
# ---------------------------------------------------------------------------

def inspect_panel_tls(host: str, port: int = 443, timeout: int = 8) -> ExecutionResult:
    """Run `openssl s_client` against a running TangoDOS panel and capture
    the cert chain, ciphers, and TLS version. Useful when the operator wants
    to confirm 'is this panel using my fleet CA or the shipped placeholder?'.
    """
    host = host.strip()
    if not host:
        return ExecutionResult([], "", "", "no host supplied", {}, False, -1)
    args = [
        "s_client",
        "-connect", f"{host}:{port}",
        "-servername", host,
        "-showcerts",
        "-brief",
    ]
    r = run_openssl(args, input_data=b"", timeout=timeout)
    log_operation("tangodos", f"inspect_panel_tls:{host}:{port}", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# 7) PKCS#12 export — one-shot upload bundle
# ---------------------------------------------------------------------------

def export_panel_pkcs12(
    cert_path: str,
    key_path: str,
    ca_path: str | None,
    out_path: str,
    friendly_name: str,
    passphrase: str,
) -> ExecutionResult:
    """Bundle a panel's cert + key (+ CA chain, optional) into a single .p12.

    The dashboard's certificate upload page accepts .p12 with a passphrase
    and splits it server-side, so this is the easiest hand-off for non-technical
    operators.
    """
    out_path = os.path.expanduser(out_path)
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    args = [
        "pkcs12", "-export",
        "-inkey", os.path.expanduser(key_path),
        "-in",    os.path.expanduser(cert_path),
        "-name",  friendly_name,
        "-passout", f"pass:{passphrase}",
        "-out", out_path,
    ]
    if ca_path:
        args += ["-certfile", os.path.expanduser(ca_path)]
    r = run_openssl(args)
    r.parsed["p12_path"] = out_path
    log_operation("tangodos", f"export_panel_pkcs12:{friendly_name}", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Misc helpers — useful for the panel UI without exposing openssl directly
# ---------------------------------------------------------------------------

def panel_file_layout() -> dict:
    """Return the canonical TangoDOS filename map (for the panel UI to display)."""
    return {
        "HTTPS cert":        HTTPS_CERT_FILENAME,
        "HTTPS key":         HTTPS_KEY_FILENAME,
        "MQTT CA":           MQTT_CA_FILENAME,
        "MQTT client cert":  MQTT_CLIENT_CERT_FILENAME,
        "MQTT client key":   MQTT_CLIENT_KEY_FILENAME,
    }
