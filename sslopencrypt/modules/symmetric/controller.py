"""
modules/symmetric/controller.py — Module 2: Symmetric Encryption & Decryption

Implementation note:
  openssl enc does NOT support AEAD modes (GCM, CCM, ChaCha20-Poly1305).
  Those modes are handled via the Python `cryptography` library, which provides
  a more complete AEAD implementation. The Command Console displays the equivalent
  openssl commands for educational purposes.

  CBC/CTR modes use openssl enc directly for full transparency.

Supported ciphers:
  AES-128/192/256 in GCM (Python cryptography), CBC, CTR (openssl enc)
  ChaCha20-Poly1305 (Python cryptography)
  3DES-CBC (legacy, deprecated warning, openssl enc)
"""

import base64
import os
import struct
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult
from core.tempfile_manager import secure_temp_file

# Safe defaults for Beginner Mode
BEGINNER_CIPHERS = [
    "AES-256-GCM",
    "AES-256-CBC",
    "ChaCha20-Poly1305",
]

# All available ciphers (Expert Mode)
ALL_CIPHERS = [
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "AES-128-CBC", "AES-192-CBC", "AES-256-CBC",
    "AES-128-CTR", "AES-192-CTR", "AES-256-CTR",
    "ChaCha20-Poly1305",
    # Deprecated — shown with warning
    "3DES-CBC",
    "DES-CBC",
]

_DEPRECATED = {"3DES-CBC", "DES-CBC"}

# Ciphers that use openssl enc
_OPENSSL_ENC_CIPHERS = {
    "AES-128-CBC": "aes-128-cbc",
    "AES-192-CBC": "aes-192-cbc",
    "AES-256-CBC": "aes-256-cbc",
    "AES-128-CTR": "aes-128-ctr",
    "AES-192-CTR": "aes-192-ctr",
    "AES-256-CTR": "aes-256-ctr",
    "3DES-CBC": "des-ede3-cbc",
    "DES-CBC": "des-cbc",
}

# Ciphers handled by Python cryptography library (AEAD)
_PYTHON_CRYPTO_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM",
    "ChaCha20-Poly1305",
}

_CBC_WARNING = (
    "CBC mode without a MAC provides confidentiality but NOT integrity. "
    "An attacker can tamper with ciphertext without detection. "
    "Prefer AES-256-GCM (AEAD) which provides both."
)

# Key sizes for AES
_AES_KEY_SIZES = {"AES-128": 16, "AES-192": 24, "AES-256": 32}


def _derive_key_iv(passphrase: str, salt: bytes, key_len: int, iv_len: int,
                   iterations: int = 600000) -> tuple[bytes, bytes]:
    """Derive key and IV from passphrase using PBKDF2-SHA256."""
    from hashlib import pbkdf2_hmac
    material = pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=key_len + iv_len)
    return material[:key_len], material[key_len:]


def _build_console_command(cipher: str, operation: str, passphrase_placeholder: str = "[PASSPHRASE]") -> str:
    """Build the equivalent openssl/Python command for educational display."""
    if cipher in _OPENSSL_ENC_CIPHERS:
        openssl_cipher = _OPENSSL_ENC_CIPHERS[cipher]
        flag = "" if operation == "encrypt" else " -d"
        return (
            f"openssl enc -{openssl_cipher}{flag} \\\n"
            f"    -in input_file -out output_file \\\n"
            f"    -pass pass:{passphrase_placeholder} -pbkdf2 -iter 600000 -salt"
        )
    elif "GCM" in cipher:
        key_bits = cipher.split("-")[1]
        return (
            f"# AES-{key_bits}-GCM (AEAD) — Python cryptography library\n"
            f"# Equivalent openssl command (informational):\n"
            f"# openssl enc -aes-{key_bits.lower()}-gcm is not supported by openssl enc\n"
            f"# Use the cryptography library: AES-{key_bits}-GCM with PBKDF2-SHA256 KDF\n"
            f"# Key: {int(key_bits)//8} bytes  IV/Nonce: 12 bytes  Tag: 16 bytes"
        )
    elif cipher == "ChaCha20-Poly1305":
        return (
            "# ChaCha20-Poly1305 (AEAD) — Python cryptography library\n"
            "# Key: 32 bytes  Nonce: 16 bytes  Tag: 16 bytes\n"
            "# PBKDF2-SHA256 key derivation, 600000 iterations"
        )
    return f"# {cipher} encryption"


def encrypt_file(
    input_path: str,
    output_path: str,
    cipher: str,
    passphrase: str,
    kdf: str = "pbkdf2",
    iterations: int = 600000,
) -> ExecutionResult:
    """Encrypt a file."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd_str = _build_console_command(cipher, "encrypt")
    is_deprecated = cipher in _DEPRECATED

    if cipher in _OPENSSL_ENC_CIPHERS:
        openssl_cipher = _OPENSSL_ENC_CIPHERS[cipher]
        cmd = [
            "enc", f"-{openssl_cipher}",
            "-in", input_path,
            "-out", output_path,
            "-pass", f"pass:{passphrase}",
            "-pbkdf2",
            "-iter", str(iterations),
            "-salt",
        ]
        r = run_openssl(cmd)
        if cipher.endswith("-CBC") and r.success:
            r.parsed["cbc_warning"] = _CBC_WARNING
        r.command_str = _build_console_command(cipher, "encrypt")
    elif cipher in _PYTHON_CRYPTO_CIPHERS:
        r = _encrypt_file_aead(input_path, output_path, cipher, passphrase, iterations)
        r.command_str = cmd_str
    else:
        r = ExecutionResult([], cmd_str, "", f"Unknown cipher: {cipher}", {}, False, -1)

    r.is_deprecated_alg = is_deprecated
    if is_deprecated:
        r.deprecated_alg_name = cipher

    log_operation(
        "symmetric", f"encrypt:{cipher}", cmd_str, r.success,
        is_deprecated=is_deprecated, deprecated_alg=cipher if is_deprecated else "",
    )
    return r


def decrypt_file(
    input_path: str,
    output_path: str,
    cipher: str,
    passphrase: str,
    iterations: int = 600000,
) -> ExecutionResult:
    """Decrypt a file."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd_str = _build_console_command(cipher, "decrypt")

    if cipher in _OPENSSL_ENC_CIPHERS:
        openssl_cipher = _OPENSSL_ENC_CIPHERS[cipher]
        cmd = [
            "enc", f"-{openssl_cipher}", "-d",
            "-in", input_path,
            "-out", output_path,
            "-pass", f"pass:{passphrase}",
            "-pbkdf2",
            "-iter", str(iterations),
        ]
        r = run_openssl(cmd)
    elif cipher in _PYTHON_CRYPTO_CIPHERS:
        r = _decrypt_file_aead(input_path, output_path, cipher, passphrase, iterations)
    else:
        r = ExecutionResult([], cmd_str, "", f"Unknown cipher: {cipher}", {}, False, -1)

    r.command_str = cmd_str
    is_deprecated = cipher in _DEPRECATED
    r.is_deprecated_alg = is_deprecated
    if is_deprecated:
        r.deprecated_alg_name = cipher
    log_operation("symmetric", f"decrypt:{cipher}", cmd_str, r.success,
                  is_deprecated=is_deprecated, deprecated_alg=cipher if is_deprecated else "")
    return r


def encrypt_text(
    plaintext: str,
    cipher: str,
    passphrase: str,
    output_format: str = "base64",
    iterations: int = 600000,
) -> ExecutionResult:
    """Encrypt a text string."""
    input_bytes = plaintext.encode("utf-8")
    cmd_str = _build_console_command(cipher, "encrypt")
    is_deprecated = cipher in _DEPRECATED

    if cipher in _OPENSSL_ENC_CIPHERS:
        openssl_cipher = _OPENSSL_ENC_CIPHERS[cipher]
        with secure_temp_file(suffix=".bin", prefix="enc_in_", content=input_bytes) as in_file:
            with secure_temp_file(suffix=".bin", prefix="enc_out_") as out_file:
                cmd = [
                    "enc", f"-{openssl_cipher}",
                    "-in", in_file.path,
                    "-out", out_file.path,
                    "-pass", f"pass:{passphrase}",
                    "-pbkdf2",
                    "-iter", str(iterations),
                    "-salt",
                ]
                r = run_openssl(cmd)
                if r.success:
                    ciphertext_bytes = out_file.read()
                    if output_format == "base64":
                        r.parsed["ciphertext"] = base64.b64encode(ciphertext_bytes).decode()
                    elif output_format == "hex":
                        r.parsed["ciphertext"] = ciphertext_bytes.hex()
                    r.stdout = r.parsed.get("ciphertext", "")
    elif cipher in _PYTHON_CRYPTO_CIPHERS:
        r = _encrypt_bytes_aead(input_bytes, cipher, passphrase, iterations)
        if r.success and output_format == "base64":
            r.parsed["ciphertext"] = base64.b64encode(r.parsed.get("ciphertext_bytes", b"")).decode()
            r.stdout = r.parsed["ciphertext"]
    else:
        r = ExecutionResult([], cmd_str, "", f"Unknown cipher: {cipher}", {}, False, -1)

    r.command_str = cmd_str
    r.is_deprecated_alg = is_deprecated
    log_operation("symmetric", f"encrypt_text:{cipher}", cmd_str, r.success)
    return r


def decrypt_text(
    ciphertext: str,
    cipher: str,
    passphrase: str,
    input_format: str = "base64",
    iterations: int = 600000,
) -> ExecutionResult:
    """Decrypt text."""
    cmd_str = _build_console_command(cipher, "decrypt")

    try:
        if input_format == "base64":
            ciphertext_bytes = base64.b64decode(ciphertext)
        elif input_format == "hex":
            ciphertext_bytes = bytes.fromhex(ciphertext)
        else:
            ciphertext_bytes = ciphertext.encode()
    except Exception as e:
        return ExecutionResult([], cmd_str, "", f"Invalid ciphertext format: {e}", {}, False, -1)

    if cipher in _OPENSSL_ENC_CIPHERS:
        openssl_cipher = _OPENSSL_ENC_CIPHERS[cipher]
        with secure_temp_file(suffix=".bin", prefix="dec_in_", content=ciphertext_bytes) as in_file:
            with secure_temp_file(suffix=".txt", prefix="dec_out_") as out_file:
                cmd = [
                    "enc", f"-{openssl_cipher}", "-d",
                    "-in", in_file.path,
                    "-out", out_file.path,
                    "-pass", f"pass:{passphrase}",
                    "-pbkdf2",
                    "-iter", str(iterations),
                ]
                r = run_openssl(cmd)
                if r.success:
                    r.stdout = out_file.read_text()
                    r.parsed["plaintext"] = r.stdout
    elif cipher in _PYTHON_CRYPTO_CIPHERS:
        r = _decrypt_bytes_aead(ciphertext_bytes, cipher, passphrase, iterations)
    else:
        r = ExecutionResult([], cmd_str, "", f"Unknown cipher: {cipher}", {}, False, -1)

    r.command_str = cmd_str
    log_operation("symmetric", f"decrypt_text:{cipher}", cmd_str, r.success)
    return r


# ---------------------------------------------------------------------------
# AEAD encryption/decryption via Python cryptography library
# Format: [16-byte salt][12-byte nonce][ciphertext][16-byte tag]
# ---------------------------------------------------------------------------

def _aead_key_size(cipher: str) -> int:
    if "128" in cipher:
        return 16
    elif "192" in cipher:
        return 24
    return 32  # 256-bit or ChaCha20


def _encrypt_file_aead(
    input_path: str, output_path: str, cipher: str, passphrase: str, iterations: int
) -> ExecutionResult:
    cmd_str = _build_console_command(cipher, "encrypt")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from hashlib import pbkdf2_hmac

        with open(input_path, "rb") as f:
            plaintext = f.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key_len = _aead_key_size(cipher)
        key = pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=key_len)

        if cipher == "ChaCha20-Poly1305":
            aead = ChaCha20Poly1305(key)
        else:
            aead = AESGCM(key)

        ciphertext_tag = aead.encrypt(nonce, plaintext, None)  # includes 16-byte tag

        # Write: salt(16) + nonce(12) + ciphertext+tag
        with open(output_path, "wb") as f:
            f.write(salt + nonce + ciphertext_tag)

        return ExecutionResult(
            command=[], command_str=cmd_str, stdout="", stderr="",
            parsed={"cipher": cipher, "salt_hex": salt.hex(), "nonce_hex": nonce.hex()},
            success=True, exit_code=0,
        )
    except ImportError:
        return ExecutionResult(
            [], cmd_str, "", "Python 'cryptography' library not installed. Run: pip install cryptography",
            {}, False, -1,
        )
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def _decrypt_file_aead(
    input_path: str, output_path: str, cipher: str, passphrase: str, iterations: int
) -> ExecutionResult:
    cmd_str = _build_console_command(cipher, "decrypt")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from cryptography.exceptions import InvalidTag
        from hashlib import pbkdf2_hmac

        with open(input_path, "rb") as f:
            data = f.read()

        if len(data) < 44:  # 16 + 12 + 16 minimum
            return ExecutionResult([], cmd_str, "", "Ciphertext too short", {}, False, -1)

        salt = data[:16]
        nonce = data[16:28]
        ciphertext_tag = data[28:]

        key_len = _aead_key_size(cipher)
        key = pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=key_len)

        if cipher == "ChaCha20-Poly1305":
            aead = ChaCha20Poly1305(key)
        else:
            aead = AESGCM(key)

        plaintext = aead.decrypt(nonce, ciphertext_tag, None)

        with open(output_path, "wb") as f:
            f.write(plaintext)

        return ExecutionResult(
            [], cmd_str, "", "", {"cipher": cipher}, True, 0,
        )
    except ImportError:
        return ExecutionResult([], cmd_str, "", "Python 'cryptography' library not installed.", {}, False, -1)
    except Exception as e:
        err = "Authentication failed — wrong passphrase or corrupted data" if "InvalidTag" in type(e).__name__ else str(e)
        return ExecutionResult([], cmd_str, "", err, {}, False, -1)


def _encrypt_bytes_aead(
    plaintext: bytes, cipher: str, passphrase: str, iterations: int
) -> ExecutionResult:
    cmd_str = _build_console_command(cipher, "encrypt")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from hashlib import pbkdf2_hmac

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key_len = _aead_key_size(cipher)
        key = pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=key_len)

        if cipher == "ChaCha20-Poly1305":
            aead = ChaCha20Poly1305(key)
        else:
            aead = AESGCM(key)

        ciphertext_tag = aead.encrypt(nonce, plaintext, None)
        full = salt + nonce + ciphertext_tag

        return ExecutionResult(
            [], cmd_str, "", "",
            {"ciphertext_bytes": full, "salt_hex": salt.hex(), "nonce_hex": nonce.hex()},
            True, 0,
        )
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def _decrypt_bytes_aead(
    data: bytes, cipher: str, passphrase: str, iterations: int
) -> ExecutionResult:
    cmd_str = _build_console_command(cipher, "decrypt")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
        from hashlib import pbkdf2_hmac

        if len(data) < 44:
            return ExecutionResult([], cmd_str, "", "Ciphertext too short", {}, False, -1)

        salt = data[:16]
        nonce = data[16:28]
        ciphertext_tag = data[28:]

        key_len = _aead_key_size(cipher)
        key = pbkdf2_hmac("sha256", passphrase.encode(), salt, iterations, dklen=key_len)

        if cipher == "ChaCha20-Poly1305":
            aead = ChaCha20Poly1305(key)
        else:
            aead = AESGCM(key)

        plaintext = aead.decrypt(nonce, ciphertext_tag, None)
        return ExecutionResult(
            [], cmd_str, plaintext.decode("utf-8", errors="replace"), "",
            {"plaintext": plaintext.decode("utf-8", errors="replace")}, True, 0,
        )
    except Exception as e:
        err = "Authentication failed — wrong passphrase or corrupted data" if "InvalidTag" in type(e).__name__ else str(e)
        return ExecutionResult([], cmd_str, "", err, {}, False, -1)


def list_supported_ciphers() -> ExecutionResult:
    """Return the list of ciphers supported by the installed OpenSSL."""
    return run_openssl(["enc", "-list"])
