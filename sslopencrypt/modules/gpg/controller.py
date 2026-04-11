"""
modules/gpg/controller.py — Module 10: GnuPG / OpenPGP Integration

Wraps gpg2 for OpenPGP operations alongside OpenSSL/X.509.
Targeted for v1.1 release.

Operations:
  - generate_key: RSA-4096, Ed25519, Cv25519
  - export_key: ASCII-armoured .asc public/private key
  - import_key: import from .asc file or keyserver
  - encrypt: encrypt file(s) for one or more recipients
  - decrypt: decrypt a .gpg/.asc file
  - sign: detached or inline signature
  - verify: verify a GPG signature
  - list_keys: list keys in the keyring
"""

from core.audit_log import log_operation
from core.executor import run_gpg
from core.result import ExecutionResult


def generate_key_batch(
    name: str,
    email: str,
    algorithm: str = "ed25519",  # "rsa4096" | "ed25519" | "cv25519"
    expiry: str = "2y",
    passphrase: str | None = None,
) -> ExecutionResult:
    """
    Generate an OpenPGP key pair using gpg --batch.
    Uses gpg2 --batch mode for scripted key generation.
    """
    passphrase_line = f"Passphrase: {passphrase}" if passphrase else "Passphrase: "
    key_type_map = {
        "rsa4096": ("RSA", "4096"),
        "ed25519": ("EDDSA", "ed25519"),
        "cv25519": ("ECDH", "cv25519"),
    }
    ktype, klen = key_type_map.get(algorithm.lower(), ("EDDSA", "ed25519"))

    batch_params = f"""%no-protection
Key-Type: {ktype}
Key-Length: {klen}
Name-Real: {name}
Name-Email: {email}
Expire-Date: {expiry}
{passphrase_line}
%commit
"""
    r = run_gpg(["--batch", "--gen-key", "-"], input_data=batch_params.encode())
    log_operation("gpg", f"generate_key:{algorithm}", r.command_str, r.success)
    return r


def export_public_key(key_id: str, output_path: str) -> ExecutionResult:
    """Export a public key as ASCII-armoured .asc."""
    cmd = ["--armor", "--export", "--output", output_path, key_id]
    r = run_gpg(cmd)
    log_operation("gpg", f"export_public_key:{key_id}", r.command_str, r.success)
    return r


def import_key(key_path: str) -> ExecutionResult:
    """Import a key from an .asc file."""
    r = run_gpg(["--import", key_path])
    log_operation("gpg", "import_key", r.command_str, r.success)
    return r


def encrypt_file(
    input_path: str,
    output_path: str,
    recipient_ids: list[str],
    sign_key_id: str | None = None,
    armor: bool = True,
) -> ExecutionResult:
    """Encrypt a file for one or more recipients."""
    cmd = ["--encrypt"]
    if armor:
        cmd.append("--armor")
    if sign_key_id:
        cmd += ["--sign", "--local-user", sign_key_id]
    for rid in recipient_ids:
        cmd += ["--recipient", rid]
    cmd += ["--output", output_path, input_path]
    r = run_gpg(cmd)
    log_operation("gpg", f"encrypt_file:{','.join(recipient_ids)}", r.command_str, r.success)
    return r


def decrypt_file(
    input_path: str,
    output_path: str,
    passphrase: str | None = None,
) -> ExecutionResult:
    """Decrypt a .gpg / .asc file."""
    cmd = ["--decrypt", "--output", output_path, input_path]
    if passphrase:
        cmd = ["--pinentry-mode", "loopback", "--passphrase", passphrase] + cmd
    r = run_gpg(cmd)
    log_operation("gpg", "decrypt_file", r.command_str, r.success)
    return r


def sign_file(
    input_path: str,
    output_path: str,
    key_id: str,
    detached: bool = True,
    armor: bool = True,
) -> ExecutionResult:
    """Sign a file with a GPG key."""
    cmd = ["--detach-sign" if detached else "--sign"]
    if armor:
        cmd.append("--armor")
    cmd += ["--local-user", key_id, "--output", output_path, input_path]
    r = run_gpg(cmd)
    log_operation("gpg", f"sign_file (detached={detached})", r.command_str, r.success)
    return r


def verify_file(
    sig_path: str,
    file_path: str | None = None,
) -> ExecutionResult:
    """Verify a GPG signature."""
    cmd = ["--verify", sig_path]
    if file_path:
        cmd.append(file_path)
    r = run_gpg(cmd)
    r.parsed["verified"] = r.success
    log_operation("gpg", "verify_file", r.command_str, r.success)
    return r


def list_keys(secret: bool = False) -> ExecutionResult:
    """List keys in the keyring."""
    cmd = ["--list-secret-keys" if secret else "--list-keys", "--with-fingerprint", "--with-colons"]
    r = run_gpg(cmd)
    return r
