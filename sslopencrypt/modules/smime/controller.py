"""
modules/smime/controller.py — Module 6: S/MIME & Email Encryption

Operations:
  - encrypt_message: encrypt an email body for a recipient (given their cert)
  - decrypt_message: decrypt a received S/MIME message
  - sign_message: S/MIME sign a message
  - verify_message: verify an S/MIME signed message
  - export_pkcs12: export a PKCS#12 bundle for Thunderbird/Outlook/Apple Mail
"""

import os
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult
from core.tempfile_manager import secure_temp_file


def encrypt_message(
    message_path: str,
    recipient_cert_path: str,
    output_path: str,
    cipher: str = "aes-256-cbc",
) -> ExecutionResult:
    """
    Encrypt an email body using the recipient's X.509 certificate.
    Uses openssl smime -encrypt.
    """
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "smime", "-encrypt",
        f"-{cipher}",
        "-in", message_path,
        "-out", output_path,
        recipient_cert_path,
    ]
    r = run_openssl(cmd)
    log_operation("smime", "encrypt_message", r.command_str, r.success)
    return r


def decrypt_message(
    message_path: str,
    key_path: str,
    cert_path: str,
    output_path: str,
    passphrase: str | None = None,
) -> ExecutionResult:
    """Decrypt an S/MIME encrypted message."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "smime", "-decrypt",
        "-in", message_path,
        "-inkey", key_path,
        "-recip", cert_path,
        "-out", output_path,
    ]
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    r = run_openssl(cmd)
    log_operation("smime", "decrypt_message", r.command_str, r.success)
    return r


def sign_message(
    message_path: str,
    key_path: str,
    cert_path: str,
    output_path: str,
    passphrase: str | None = None,
    detached: bool = True,
) -> ExecutionResult:
    """S/MIME sign a message."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "smime", "-sign",
        "-in", message_path,
        "-inkey", key_path,
        "-signer", cert_path,
        "-out", output_path,
    ]
    if not detached:
        cmd.append("-nodetach")   # OpenSSL 3.x: detached is default; -nodetach makes it opaque
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    r = run_openssl(cmd)
    log_operation("smime", "sign_message", r.command_str, r.success)
    return r


def verify_message(
    message_path: str,
    ca_bundle: str | None = None,
    output_path: str | None = None,
) -> ExecutionResult:
    """Verify an S/MIME signed message."""
    cmd = ["smime", "-verify", "-in", message_path]
    if ca_bundle:
        cmd += ["-CAfile", ca_bundle]
    else:
        cmd += ["-noverify"]
    if output_path:
        cmd += ["-out", output_path]
    r = run_openssl(cmd)
    r.parsed["verified"] = r.success
    log_operation("smime", "verify_message", r.command_str, r.success)
    return r
