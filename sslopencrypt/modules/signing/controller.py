"""
modules/signing/controller.py — Module 5: Document & File Signing

Operations:
  - sign_file: create a detached PKCS#7 CMS signature (.p7s)
  - verify_file: verify a detached or embedded signature
  - sign_raw: produce a raw ECDSA/RSA signature over a file digest
  - verify_raw: verify a raw signature
  - timestamp: request an RFC 3161 timestamp token from a TSA
  - batch_sign: sign all files matching a glob pattern
  - verify_bin_signed: verify RP2350-style .bin.signed firmware (ECDSA-P256)
"""

import os
import re
import struct
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult
from core.tempfile_manager import secure_temp_file

# Public TSA endpoints for RFC 3161 timestamps
PUBLIC_TSA_URLS = {
    "DigiCert":  "http://timestamp.digicert.com",
    "Sectigo":   "http://timestamp.sectigo.com",
    "FreeTSA":   "https://freetsa.org/tsr",
    "GlobalSign": "http://timestamp.globalsign.com/scripts/timstamp.dll",
}


# ---------------------------------------------------------------------------
# PKCS#7 / CMS Detached Signature
# ---------------------------------------------------------------------------

def sign_file(
    file_path: str,
    key_path: str,
    cert_path: str,
    output_sig: str,
    digest: str = "sha256",
    passphrase: str | None = None,
    ca_bundle: str | None = None,
    detached: bool = True,
) -> ExecutionResult:
    """
    Create a CMS/PKCS#7 digital signature.

    Output: .p7s file (detached) or .p7m file (embedded/opaque).
    """
    output_sig = os.path.expanduser(output_sig)
    Path(output_sig).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "cms", "-sign",
        "-in", file_path,
        "-inkey", key_path,
        "-signer", cert_path,
        f"-md", digest,
        "-out", output_sig,
        "-outform", "PEM",
    ]
    if not detached:
        cmd.append("-nodetach")   # OpenSSL 3.x: detached is default; -nodetach makes it opaque
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    if ca_bundle:
        cmd += ["-certfile", ca_bundle]

    r = run_openssl(cmd)
    log_operation(
        "signing", f"sign_file (CMS detached={detached})",
        r.command_str, r.success,
    )
    return r


def verify_file(
    file_path: str,
    sig_path: str,
    ca_bundle: str | None = None,
    no_verify_cert: bool = False,
) -> ExecutionResult:
    """Verify a detached CMS/PKCS#7 signature."""
    cmd = [
        "cms", "-verify",
        "-in", sig_path,
        "-inform", "PEM",
        "-content", file_path,
    ]
    if ca_bundle:
        cmd += ["-CAfile", ca_bundle]
    if no_verify_cert:
        cmd.append("-noverify")

    r = run_openssl(cmd)
    r.parsed["verified"] = r.success

    # Extract signer info from CMS output
    if r.stdout or r.stderr:
        m = re.search(r"Signer certificate\s*\n(.*)", r.stdout + r.stderr, re.MULTILINE)
        if m:
            r.parsed["signer_info"] = m.group(1).strip()

    log_operation("signing", "verify_file (CMS)", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Raw RSA/ECDSA signature
# ---------------------------------------------------------------------------

def _is_eddsa_key(key_path: str) -> bool:
    """Return True if the key file is an Ed25519 or Ed448 key."""
    try:
        with open(key_path, "r", errors="ignore") as f:
            content = f.read(2048)
        # Run pkey -text to detect algorithm
        r = run_openssl(["pkey", "-in", key_path, "-text", "-noout"])
        text = (r.stdout + r.stderr).upper()
        return "ED25519" in text or "ED448" in text
    except Exception:
        return False


def sign_raw(
    file_path: str,
    key_path: str,
    sig_output: str,
    digest: str = "sha256",
    passphrase: str | None = None,
) -> ExecutionResult:
    """
    Produce a raw DER-encoded signature over the file digest.
    This is the format used by the RP2350 OTA signing pipeline.

    For RSA/ECDSA keys: uses openssl dgst -{digest} -sign.
    For Ed25519/Ed448 keys: uses openssl pkeyutl -sign -rawin (EdDSA hashes internally).
    """
    sig_output = os.path.expanduser(sig_output)
    Path(sig_output).parent.mkdir(parents=True, exist_ok=True)

    if _is_eddsa_key(key_path):
        cmd = ["pkeyutl", "-sign", "-rawin", "-inkey", key_path, "-in", file_path, "-out", sig_output]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
        r = run_openssl(cmd)
        log_operation("signing", "sign_raw (pkeyutl -rawin)", r.command_str, r.success)
    else:
        cmd = [
            "dgst", f"-{digest}",
            "-sign", key_path,
            "-out", sig_output,
            file_path,
        ]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
        r = run_openssl(cmd)
        log_operation("signing", f"sign_raw (dgst -{digest})", r.command_str, r.success)
    return r


def verify_raw(
    file_path: str,
    sig_path: str,
    pub_key_path: str,
    digest: str = "sha256",
) -> ExecutionResult:
    """
    Verify a raw DER-encoded signature.
    For Ed25519/Ed448: uses pkeyutl -verify -rawin.
    For RSA/ECDSA: uses dgst -{digest} -verify.
    """
    if _is_eddsa_key(pub_key_path):
        cmd = ["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub_key_path,
               "-in", file_path, "-sigfile", sig_path]
        r = run_openssl(cmd)
        r.parsed["verified"] = r.success
        log_operation("signing", "verify_raw (pkeyutl -rawin)", r.command_str, r.success)
    else:
        cmd = [
            "dgst", f"-{digest}",
            "-verify", pub_key_path,
            "-signature", sig_path,
            file_path,
        ]
        r = run_openssl(cmd)
        r.parsed["verified"] = r.success
        log_operation("signing", "verify_raw", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# RFC 3161 Timestamp
# ---------------------------------------------------------------------------

def request_timestamp(
    file_path: str,
    tsr_output: str,
    tsa_url: str = "http://timestamp.digicert.com",
    digest: str = "sha256",
) -> ExecutionResult:
    """
    Request an RFC 3161 timestamp token from a public TSA.

    Steps:
      1. openssl ts -query -data <file> -no_nonce -sha256 -cert -out <tsq>
      2. curl POST tsq to TSA URL → tsr
      3. openssl ts -verify -data <file> -in <tsr> -CAfile <cacerts>
    """
    tsr_output = os.path.expanduser(tsr_output)
    Path(tsr_output).parent.mkdir(parents=True, exist_ok=True)
    import urllib.request

    with secure_temp_file(suffix=".tsq", prefix="ts_") as tsq_file:
        # Step 1: generate timestamp request
        cmd_query = [
            "ts", "-query",
            "-data", file_path,
            f"-{digest}",
            "-cert",
            "-out", tsq_file.path,
        ]
        r_query = run_openssl(cmd_query)
        if not r_query.success:
            return r_query

        # Step 2: send to TSA
        try:
            req = urllib.request.Request(
                tsa_url,
                data=tsq_file.read(),
                headers={"Content-Type": "application/timestamp-query"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                tsr_bytes = resp.read()
            with open(tsr_output, "wb") as f:
                f.write(tsr_bytes)
            r_query.parsed["tsr_path"] = tsr_output
            r_query.parsed["tsa_url"] = tsa_url
        except Exception as e:
            r_query.success = False
            r_query.stderr = f"TSA request failed: {e}"

    log_operation("signing", "request_timestamp", r_query.command_str, r_query.success)
    return r_query


def verify_timestamp(
    file_path: str,
    tsr_path: str,
    ca_bundle: str | None = None,
) -> ExecutionResult:
    """Verify an RFC 3161 timestamp token."""
    cmd = ["ts", "-verify", "-data", file_path, "-in", tsr_path]
    if ca_bundle:
        cmd += ["-CAfile", ca_bundle]
    else:
        cmd += ["-CAfile", "/etc/ssl/certs/ca-certificates.crt"]
    r = run_openssl(cmd)
    r.parsed["verified"] = r.success
    log_operation("signing", "verify_timestamp", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Batch signing
# ---------------------------------------------------------------------------

def batch_sign(
    directory: str,
    pattern: str,
    key_path: str,
    cert_path: str,
    passphrase: str | None = None,
    digest: str = "sha256",
) -> list[ExecutionResult]:
    """Sign all files matching a glob pattern in a directory."""
    results = []
    base = Path(directory)
    for fpath in sorted(base.glob(pattern)):
        if fpath.is_file():
            sig_out = str(fpath) + ".p7s"
            r = sign_file(str(fpath), key_path, cert_path, sig_out,
                          digest=digest, passphrase=passphrase)
            results.append(r)
    return results


# ---------------------------------------------------------------------------
# RP2350 / Pico 2W .bin.signed verification
# ---------------------------------------------------------------------------

def verify_bin_signed(
    bin_signed_path: str,
    pub_key_path: str,
) -> ExecutionResult:
    """
    Verify a .bin.signed firmware file produced by the Earle Philhower signing.py hook.

    Format: raw binary + DER-encoded ECDSA-P256 signature (72-80 bytes)
            + 4-byte length marker (0x00 0x01 0x00 0x00)
    """
    with open(bin_signed_path, "rb") as f:
        data = f.read()

    # Locate the 4-byte marker 0x00 0x01 0x00 0x00
    marker = b"\x00\x01\x00\x00"
    marker_pos = data.rfind(marker)
    if marker_pos < 0:
        r = ExecutionResult(
            command=[], command_str="", stdout="",
            stderr="Marker 0x00010000 not found — this does not appear to be a .bin.signed file.",
            parsed={}, success=False, exit_code=-1,
        )
        return r

    sig_len_bytes = data[marker_pos - 2:marker_pos]
    # DER ECDSA sigs are 70-72 bytes for P-256; try to find a plausible sig
    # The signature immediately precedes the 4-byte length marker
    # Scan backwards for DER SEQUENCE (0x30) tag
    sig_start = None
    for offset in range(marker_pos - 72, marker_pos - 60):
        if offset >= 0 and data[offset] == 0x30:
            sig_start = offset
            break

    if sig_start is None:
        r = ExecutionResult(
            command=[], command_str="",
            stdout="", stderr="Could not locate DER ECDSA signature in .bin.signed file.",
            parsed={}, success=False, exit_code=-1,
        )
        return r

    binary_body = data[:sig_start]
    signature_der = data[sig_start:marker_pos]

    with (
        secure_temp_file(suffix=".bin", prefix="body_") as body_file,
        secure_temp_file(suffix=".sig", prefix="sig_") as sig_file,
    ):
        body_file.write(binary_body)
        sig_file.write(signature_der)

        r = verify_raw(
            file_path=body_file.path,
            sig_path=sig_file.path,
            pub_key_path=pub_key_path,
            digest="sha256",
        )

    r.parsed["firmware_size_bytes"] = len(binary_body)
    r.parsed["signature_size_bytes"] = len(signature_der)
    r.parsed["total_file_size"] = len(data)

    log_operation("signing", "verify_bin_signed (RP2350)", r.command_str, r.success)
    return r
