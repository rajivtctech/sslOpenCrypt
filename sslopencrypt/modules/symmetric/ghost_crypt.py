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


# ---------------------------------------------------------------------------
# Ghost Crypt v1.2 — dual-layer deniable container
# ---------------------------------------------------------------------------

DENIABLE_CAP_ALIGN = 64   # capacity rounded up to this boundary (bytes)
DENIABLE_LEN_PREFIX = 4   # bytes reserved at the head of each segment for content length


def _deniable_capacity(real_size: int, decoy_size: int) -> int:
    """Return per-segment capacity (content area) for a deniable container."""
    raw = max(real_size, decoy_size) + DENIABLE_LEN_PREFIX
    return ((raw + DENIABLE_CAP_ALIGN - 1) // DENIABLE_CAP_ALIGN) * DENIABLE_CAP_ALIGN


def _encode_deniable_plaintext(plaintext: bytes, capacity: int) -> bytes:
    """
    Encode plaintext for a deniable segment:
      [4-byte length big-endian] [plaintext] [random padding to capacity]
    """
    usable = capacity - DENIABLE_LEN_PREFIX
    if len(plaintext) > usable:
        raise ValueError(f"Plaintext ({len(plaintext)} B) exceeds usable capacity ({usable} B)")
    length_prefix = len(plaintext).to_bytes(DENIABLE_LEN_PREFIX, "big")
    padding = os.urandom(usable - len(plaintext))
    return length_prefix + plaintext + padding


def _decode_deniable_plaintext(padded: bytes) -> bytes:
    """Extract the original plaintext from a decoded (length-prefixed + padded) block."""
    length = int.from_bytes(padded[:DENIABLE_LEN_PREFIX], "big")
    return padded[DENIABLE_LEN_PREFIX : DENIABLE_LEN_PREFIX + length]


def _make_deniable_segment(plaintext: bytes, capacity: int, passphrase: str, cipher: str) -> bytes:
    """Encrypt plaintext into a fixed-capacity deniable segment."""
    salt = os.urandom(GHOST_SALT_LEN)
    nonce = os.urandom(GHOST_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    padded = _encode_deniable_plaintext(plaintext, capacity)
    ciphertext_tag = _aead_encrypt(key, nonce, padded, cipher)
    return salt + nonce + ciphertext_tag  # total = CAPACITY + GHOST_OVERHEAD


def _open_deniable_segment(segment: bytes, passphrase: str, cipher: str) -> bytes | None:
    """
    Try to decrypt one segment of a deniable container.
    Returns the original plaintext bytes on success, None on authentication failure.
    """
    if len(segment) < GHOST_OVERHEAD:
        return None
    salt = segment[:GHOST_SALT_LEN]
    nonce = segment[GHOST_SALT_LEN : GHOST_SALT_LEN + GHOST_NONCE_LEN]
    ciphertext_tag = segment[GHOST_SALT_LEN + GHOST_NONCE_LEN :]
    try:
        key = _derive_key(passphrase, salt)
        padded = _aead_decrypt(key, nonce, ciphertext_tag, cipher)
        return _decode_deniable_plaintext(padded)
    except Exception:
        return None


def _deniable_console_cmd(cipher: str) -> str:
    return (
        "# Ghost Crypt v1.2 — dual-layer deniable container\n"
        "# Layout: segment_0 (real, passphrase A) || segment_1 (decoy, passphrase B)\n"
        "# Each segment: salt(32) + nonce(12) + AEAD_encrypt(4-byte-len || content || pad) + tag(16)\n"
        f"# Cipher: {cipher}  |  KDF: Argon2id t=3 m=64MiB p=4\n"
        "# Under coercion: reveal the DECOY passphrase only."
    )


def create_deniable_container(
    real_path: str,
    decoy_path: str,
    output_path: str,
    real_passphrase: str,
    decoy_passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """
    Create a Ghost Crypt v1.2 dual-layer deniable container.

    The container holds two independently encrypted payloads in a fixed-capacity
    binary blob that carries no magic bytes, headers, or layer count.

      - Segment 0 encrypts the REAL content  (real_passphrase)
      - Segment 1 encrypts the DECOY content (decoy_passphrase)

    Under coercion, reveal only the decoy passphrase.  The opener will
    successfully decrypt the decoy content from segment 1.  The existence of
    a second payload cannot be cryptographically proven without the real passphrase.

    Binary layout (no magic, no header):
      Bytes [0,            SEGMENT_SIZE)  : segment_0 — real content
      Bytes [SEGMENT_SIZE, 2*SEGMENT_SIZE): segment_1 — decoy content

      SEGMENT_SIZE = CAPACITY + GHOST_OVERHEAD (60)
      CAPACITY     = ceil((max(real_size, decoy_size) + 4) / 64) × 64

      Each segment: salt(32) + nonce(12) + AEAD_encrypt(4-byte-len || content || pad) + tag(16)
    """
    cmd_str = _deniable_console_cmd(cipher)

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    try:
        real_bytes = Path(real_path).read_bytes()
    except OSError as e:
        return ExecutionResult([], cmd_str, "", f"Cannot read real content: {e}", {}, False, -1)

    try:
        decoy_bytes = Path(decoy_path).read_bytes()
    except OSError as e:
        return ExecutionResult([], cmd_str, "", f"Cannot read decoy content: {e}", {}, False, -1)

    try:
        capacity = _deniable_capacity(len(real_bytes), len(decoy_bytes))
        segment_0 = _make_deniable_segment(real_bytes, capacity, real_passphrase, cipher)
        segment_1 = _make_deniable_segment(decoy_bytes, capacity, decoy_passphrase, cipher)
        container = segment_0 + segment_1

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(container)
        os.chmod(output_path, 0o600)

        segment_size = capacity + GHOST_OVERHEAD
        parsed = {
            "cipher": cipher,
            "real_size": len(real_bytes),
            "decoy_size": len(decoy_bytes),
            "capacity": capacity,
            "segment_size": segment_size,
            "container_size": len(container),
            "version": "1.2",
        }
        log_operation("ghost_crypt", f"deniable_create:{cipher}", cmd_str, True)
        return ExecutionResult(
            [], cmd_str,
            f"Deniable container created ({len(container)} bytes, 2 × {segment_size}B segments)",
            "", parsed, True, 0,
        )

    except ImportError as e:
        return ExecutionResult([], cmd_str, "", f"Missing dependency: {e}. Install: pip install cryptography argon2-cffi", {}, False, -1)
    except Exception as e:
        log_operation("ghost_crypt", f"deniable_create:{cipher}", cmd_str, False)
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def open_deniable_container(
    input_path: str,
    output_path: str,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """
    Open a Ghost Crypt v1.2 deniable container.

    Tries both segments with the given passphrase and returns whichever
    authenticates successfully.  The caller does not need to know (and should
    not know) which segment holds the real vs. decoy content.
    """
    cmd_str = (
        "# Ghost Crypt v1.2 — open deniable container\n"
        f"# Tries both segments; returns whichever the passphrase decrypts ({cipher})"
    )

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    try:
        data = Path(input_path).read_bytes()
    except OSError as e:
        return ExecutionResult([], cmd_str, "", f"Cannot read container: {e}", {}, False, -1)

    if len(data) < 2 * GHOST_OVERHEAD or len(data) % 2 != 0:
        return ExecutionResult(
            [], cmd_str, "",
            f"Not a valid deniable container (size {len(data)} B; expected even size ≥ {2 * GHOST_OVERHEAD})",
            {}, False, -1,
        )

    try:
        segment_size = len(data) // 2
        plaintext = _open_deniable_segment(data[:segment_size], passphrase, cipher)
        segment_used = 0
        if plaintext is None:
            plaintext = _open_deniable_segment(data[segment_size:], passphrase, cipher)
            segment_used = 1

        if plaintext is None:
            return ExecutionResult(
                [], cmd_str, "",
                "Authentication failed — wrong passphrase or not a deniable container",
                {}, False, -1,
            )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_bytes(plaintext)
        os.chmod(output_path, 0o600)

        parsed = {
            "cipher": cipher,
            "plaintext_size": len(plaintext),
            "container_size": len(data),
            "segment_used": segment_used,
            "version": "1.2",
        }
        log_operation("ghost_crypt", f"deniable_open:{cipher}", cmd_str, True)
        return ExecutionResult([], cmd_str, f"Decrypted ({len(plaintext)} bytes)", "", parsed, True, 0)

    except ImportError as e:
        return ExecutionResult([], cmd_str, "", f"Missing dependency: {e}. Install: pip install cryptography argon2-cffi", {}, False, -1)
    except Exception as e:
        log_operation("ghost_crypt", f"deniable_open:{cipher}", cmd_str, False)
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def create_deniable_from_bytes(
    real_bytes: bytes,
    decoy_bytes: bytes,
    real_passphrase: str,
    decoy_passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """Create a deniable container from raw bytes. Returns container bytes in parsed['container_bytes']."""
    cmd_str = _deniable_console_cmd(cipher)

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    try:
        capacity = _deniable_capacity(len(real_bytes), len(decoy_bytes))
        segment_0 = _make_deniable_segment(real_bytes, capacity, real_passphrase, cipher)
        segment_1 = _make_deniable_segment(decoy_bytes, capacity, decoy_passphrase, cipher)
        container = segment_0 + segment_1

        parsed = {
            "container_bytes": container,
            "cipher": cipher,
            "capacity": capacity,
            "segment_size": capacity + GHOST_OVERHEAD,
            "container_size": len(container),
            "version": "1.2",
        }
        log_operation("ghost_crypt", f"deniable_create_bytes:{cipher}", cmd_str, True)
        return ExecutionResult([], cmd_str, f"Deniable container: {len(container)} bytes", "", parsed, True, 0)

    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def open_deniable_from_bytes(
    container: bytes,
    passphrase: str,
    cipher: str = "AES-256-GCM",
) -> ExecutionResult:
    """Open a deniable container from raw bytes. Returns plaintext in parsed['plaintext_bytes']."""
    cmd_str = (
        f"# Ghost Crypt v1.2 — open deniable container from bytes ({cipher})"
    )

    if cipher not in SUPPORTED_CIPHERS:
        return ExecutionResult([], cmd_str, "", f"Unsupported cipher: {cipher}", {}, False, -1)

    if len(container) < 2 * GHOST_OVERHEAD or len(container) % 2 != 0:
        return ExecutionResult(
            [], cmd_str, "",
            f"Not a valid deniable container (size {len(container)} B; expected even size ≥ {2 * GHOST_OVERHEAD})",
            {}, False, -1,
        )

    try:
        segment_size = len(container) // 2
        plaintext = _open_deniable_segment(container[:segment_size], passphrase, cipher)
        if plaintext is None:
            plaintext = _open_deniable_segment(container[segment_size:], passphrase, cipher)
        if plaintext is None:
            return ExecutionResult(
                [], cmd_str, "",
                "Authentication failed — wrong passphrase or not a deniable container",
                {}, False, -1,
            )

        log_operation("ghost_crypt", f"deniable_open_bytes:{cipher}", cmd_str, True)
        return ExecutionResult(
            [], cmd_str, f"Decrypted: {len(plaintext)} bytes", "",
            {"plaintext_bytes": plaintext, "plaintext_size": len(plaintext), "version": "1.2"},
            True, 0,
        )

    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


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
