"""
modules/symmetric/ghost_crypt.py — Ghost Crypt: deniable, headerless encrypted container.

Specification (Complete Book, Section 8B):
  A Ghost Crypt container is a binary file whose content is computationally
  indistinguishable from random noise. It carries no magic bytes, no header,
  no length field — only the person who knows the passphrase can identify it.

Binary layout (no header, no magic):
  Bytes  0–31       : salt       (32 bytes, CSPRNG — fed to Argon2id KDF)
  Bytes 32–43       : nonce/IV   (12 bytes, CSPRNG — fed to AES-256-GCM)
  Bytes 44–(N-16)   : ciphertext (N − 60 bytes of AES-256-GCM output)
  Bytes (N-16)–N    : GCM auth tag (16 bytes)

  Total wire size = payload_size + 60 bytes.

Key derivation:
  Algorithm   : Argon2id (RFC 9106)
  Time cost   : 3 iterations
  Memory cost : 65536 KiB (64 MiB)
  Parallelism : 4 lanes
  Output      : 32 bytes (256-bit AES-256-GCM key)

Alternative cipher: ChaCha20-Poly1305 (same layout, 32-byte key, 12-byte nonce).

Ghost Crypt is gated to Expert Mode. It is not visible in Beginner Mode.
"""

import os
from pathlib import Path

from core.audit_log import log_operation
from core.result import ExecutionResult


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GHOST_SALT_LEN = 32
GHOST_NONCE_LEN = 12
GHOST_TAG_LEN = 16
GHOST_OVERHEAD = GHOST_SALT_LEN + GHOST_NONCE_LEN + GHOST_TAG_LEN  # 60 bytes

# Argon2id parameters (matches spec)
_ARGON2_TIME_COST = 3
_ARGON2_MEMORY_COST = 65536  # KiB
_ARGON2_PARALLELISM = 4
_ARGON2_HASH_LEN = 32

SUPPORTED_CIPHERS = ["AES-256-GCM", "ChaCha20-Poly1305"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from passphrase + salt using Argon2id."""
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LEN,
            type=Type.ID,
        )
    except ImportError:
        # Fallback: PBKDF2-SHA512 with 600,000 iterations
        from hashlib import pbkdf2_hmac
        return pbkdf2_hmac("sha512", passphrase.encode("utf-8"), salt, 600000, dklen=32)


def _aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, cipher: str) -> bytes:
    """Encrypt and return ciphertext+tag (16-byte tag appended by library)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    if cipher == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return AESGCM(key).encrypt(nonce, plaintext, None)


def _aead_decrypt(key: bytes, nonce: bytes, ciphertext_tag: bytes, cipher: str) -> bytes:
    """Decrypt ciphertext+tag; raises cryptography.exceptions.InvalidTag on failure."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    if cipher == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext_tag, None)
    return AESGCM(key).decrypt(nonce, ciphertext_tag, None)


def _console_cmd(cipher: str, operation: str) -> str:
    """Return the educational equivalent shell commands for the console."""
    kdf_note = (
        "# Key derivation: Argon2id  t=3  m=64MiB  p=4  out=32 bytes\n"
        "# (Standalone recovery uses PBKDF2-SHA512 600k iters — see docs)\n"
    )
    if cipher == "AES-256-GCM":
        if operation == "encrypt":
            return (
                "# Ghost Crypt — AES-256-GCM, Argon2id KDF, no header\n"
                + kdf_note
                + "SALT=$(openssl rand -hex 32)\n"
                "IV=$(openssl rand -hex 12)\n"
                "KEY=$(derive_argon2id \"$PASSPHRASE\" \"$SALT\")\n"
                "openssl enc -aes-256-gcm \\\n"
                "    -K \"$KEY\" -iv \"$IV\" \\\n"
                "    -in plaintext.bin -out ghost.bin\n"
                "# Output: salt(32) + nonce(12) + ciphertext + tag(16)"
            )
        else:
            return (
                "# Ghost Crypt — AES-256-GCM decrypt\n"
                + kdf_note
                + "SALT=$(dd if=ghost.bin bs=1 count=32 | xxd -p -c 64)\n"
                "IV=$(dd if=ghost.bin bs=1 skip=32 count=12 | xxd -p -c 24)\n"
                "KEY=$(derive_argon2id \"$PASSPHRASE\" \"$SALT\")\n"
                "dd if=ghost.bin bs=1 skip=44 | \\\n"
                "    openssl enc -d -aes-256-gcm -K \"$KEY\" -iv \"$IV\" \\\n"
                "    -out plaintext_recovered.bin"
            )
    else:  # ChaCha20-Poly1305
        if operation == "encrypt":
            return (
                "# Ghost Crypt — ChaCha20-Poly1305, Argon2id KDF, no header\n"
                + kdf_note
                + "# Python: ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)\n"
                "# Output: salt(32) + nonce(12) + ciphertext + tag(16)"
            )
        else:
            return (
                "# Ghost Crypt — ChaCha20-Poly1305 decrypt\n"
                + kdf_note
                + "# Python: ChaCha20Poly1305(key).decrypt(nonce, ciphertext_tag, None)"
            )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_container(
    input_path: str,
    output_path: str,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """
    Create a Ghost Crypt container from a plaintext file.

    Reads input_path, encrypts with Argon2id-derived key, writes headerless
    container to output_path.
    """
    cmd_str = _console_cmd(cipher, "encrypt")

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    try:
        plaintext = Path(input_path).read_bytes()
    except OSError as e:
        return ExecutionResult([], cmd_str, "", f"Cannot read input: {e}", {}, False, -1)

    try:
        salt = os.urandom(GHOST_SALT_LEN)
        nonce = os.urandom(GHOST_NONCE_LEN)
        key = _derive_key(passphrase, salt)
        ciphertext_tag = _aead_encrypt(key, nonce, plaintext, cipher)

        container = salt + nonce + ciphertext_tag
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(container)
        # Secure permissions
        os.chmod(output_path, 0o600)

        parsed = {
            "cipher": cipher,
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
            "plaintext_size": len(plaintext),
            "container_size": len(container),
            "overhead_bytes": GHOST_OVERHEAD,
        }
        log_operation("ghost_crypt", f"create:{cipher}", cmd_str, True)
        return ExecutionResult([], cmd_str, f"Container created ({len(container)} bytes)", "", parsed, True, 0)

    except ImportError as e:
        msg = f"Missing dependency: {e}. Install: pip install cryptography argon2-cffi"
        return ExecutionResult([], cmd_str, "", msg, {}, False, -1)
    except Exception as e:
        log_operation("ghost_crypt", f"create:{cipher}", cmd_str, False)
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def open_container(
    input_path: str,
    output_path: str,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """
    Open (decrypt) a Ghost Crypt container to a plaintext file.

    The cipher must match what was used to create the container.
    """
    cmd_str = _console_cmd(cipher, "decrypt")

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    try:
        data = Path(input_path).read_bytes()
    except OSError as e:
        return ExecutionResult([], cmd_str, "", f"Cannot read container: {e}", {}, False, -1)

    if len(data) < GHOST_OVERHEAD:
        return ExecutionResult(
            [], cmd_str, "",
            f"File too small to be a Ghost Crypt container (need ≥{GHOST_OVERHEAD} bytes, got {len(data)})",
            {}, False, -1,
        )

    try:
        salt = data[:GHOST_SALT_LEN]
        nonce = data[GHOST_SALT_LEN:GHOST_SALT_LEN + GHOST_NONCE_LEN]
        ciphertext_tag = data[GHOST_SALT_LEN + GHOST_NONCE_LEN:]

        key = _derive_key(passphrase, salt)
        plaintext = _aead_decrypt(key, nonce, ciphertext_tag, cipher)

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(plaintext)
        os.chmod(output_path, 0o600)

        parsed = {
            "cipher": cipher,
            "plaintext_size": len(plaintext),
            "container_size": len(data),
        }
        log_operation("ghost_crypt", f"open:{cipher}", cmd_str, True)
        return ExecutionResult([], cmd_str, f"Decrypted ({len(plaintext)} bytes)", "", parsed, True, 0)

    except ImportError as e:
        msg = f"Missing dependency: {e}. Install: pip install cryptography argon2-cffi"
        return ExecutionResult([], cmd_str, "", msg, {}, False, -1)
    except Exception as e:
        is_auth = "InvalidTag" in type(e).__name__ or "invalid tag" in str(e).lower()
        err = "Authentication failed — wrong passphrase or corrupted container" if is_auth else str(e)
        log_operation("ghost_crypt", f"open:{cipher}", cmd_str, False)
        return ExecutionResult([], cmd_str, "", err, {}, False, -1)


def create_container_from_bytes(
    plaintext: bytes,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """Create a Ghost Crypt container from raw bytes; returns container bytes in parsed."""
    cmd_str = _console_cmd(cipher, "encrypt")

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    try:
        salt = os.urandom(GHOST_SALT_LEN)
        nonce = os.urandom(GHOST_NONCE_LEN)
        key = _derive_key(passphrase, salt)
        ciphertext_tag = _aead_encrypt(key, nonce, plaintext, cipher)
        container = salt + nonce + ciphertext_tag

        parsed = {
            "container_bytes": container,
            "cipher": cipher,
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
            "overhead_bytes": GHOST_OVERHEAD,
        }
        log_operation("ghost_crypt", f"create_bytes:{cipher}", cmd_str, True)
        return ExecutionResult([], cmd_str, f"Container: {len(container)} bytes", "", parsed, True, 0)

    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def open_container_from_bytes(
    container: bytes,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """Open a Ghost Crypt container from raw bytes; returns plaintext in parsed."""
    cmd_str = _console_cmd(cipher, "decrypt")

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    if len(container) < GHOST_OVERHEAD:
        return ExecutionResult(
            [], cmd_str, "",
            f"Data too small for a Ghost Crypt container (need ≥{GHOST_OVERHEAD} bytes)",
            {}, False, -1,
        )

    try:
        salt = container[:GHOST_SALT_LEN]
        nonce = container[GHOST_SALT_LEN:GHOST_SALT_LEN + GHOST_NONCE_LEN]
        ciphertext_tag = container[GHOST_SALT_LEN + GHOST_NONCE_LEN:]

        key = _derive_key(passphrase, salt)
        plaintext = _aead_decrypt(key, nonce, ciphertext_tag, cipher)

        log_operation("ghost_crypt", f"open_bytes:{cipher}", cmd_str, True)
        return ExecutionResult([], cmd_str, f"Decrypted: {len(plaintext)} bytes", "",
                               {"plaintext_bytes": plaintext, "plaintext_size": len(plaintext)}, True, 0)

    except Exception as e:
        is_auth = "InvalidTag" in type(e).__name__ or "invalid tag" in str(e).lower()
        err = "Authentication failed — wrong passphrase or corrupted container" if is_auth else str(e)
        log_operation("ghost_crypt", f"open_bytes:{cipher}", cmd_str, False)
        return ExecutionResult([], cmd_str, "", err, {}, False, -1)
