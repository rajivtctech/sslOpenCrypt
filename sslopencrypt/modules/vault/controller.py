"""
modules/vault/controller.py — Module 11: Encrypted Key Vault

Stores private keys in a single encrypted container at ~/.sslopencrypt/vault.enc.

Security design:
  - Master passphrase → 32-byte key via Argon2id (time=3, mem=65536 KiB, p=1)
  - Payload encrypted with AES-256-GCM (Python cryptography library)
  - Fresh random salt (32 bytes) and nonce (12 bytes) per save
  - File permissions: 0o600

Vault file binary layout:
  [4 bytes  magic  b"SSVC"]
  [1 byte   version = 1]
  [32 bytes Argon2id salt]
  [12 bytes AES-GCM nonce]
  [N bytes  AES-GCM ciphertext + 16-byte tag]

Decrypted payload is UTF-8 JSON:
  {
    "version": 1,
    "entries": [
      {
        "id":         str (UUID4),
        "name":       str,
        "algorithm":  str (e.g. "ECDSA-P256"),
        "created_at": str (ISO-8601),
        "pem":        str (private key PEM),
        "tags":       list[str],
        "comment":    str
      }
    ]
  }
"""

import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.audit_log import log_operation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VAULT_MAGIC = b"SSVC"
VAULT_VERSION = 1
_ARGON2_TIME_COST   = 3
_ARGON2_MEMORY_COST = 65536   # 64 MiB
_ARGON2_PARALLELISM = 1
_ARGON2_HASH_LEN    = 32


def _vault_path() -> Path:
    base = Path.home() / ".sslopencrypt"
    base.mkdir(mode=0o700, exist_ok=True)
    return base / "vault.enc"


# ---------------------------------------------------------------------------
# In-memory vault state (simple module-level singleton)
# ---------------------------------------------------------------------------

_vault_data: dict | None = None   # None = locked
_vault_passphrase: str | None = None


def is_unlocked() -> bool:
    return _vault_data is not None


def is_vault_exists() -> bool:
    return _vault_path().exists()


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from passphrase + salt using Argon2id."""
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
        # Fallback: PBKDF2-SHA256 (weaker but functional without argon2-cffi)
        from hashlib import pbkdf2_hmac
        return pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 600_000, dklen=32)


# ---------------------------------------------------------------------------
# Encryption / decryption
# ---------------------------------------------------------------------------

def _encrypt_payload(payload_json: str, passphrase: str) -> bytes:
    """Encrypt the JSON payload and return the full vault binary."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt  = os.urandom(32)
    nonce = os.urandom(12)
    key   = _derive_key(passphrase, salt)

    aead = AESGCM(key)
    ciphertext = aead.encrypt(nonce, payload_json.encode("utf-8"), None)

    return VAULT_MAGIC + bytes([VAULT_VERSION]) + salt + nonce + ciphertext


def _decrypt_payload(data: bytes, passphrase: str) -> str:
    """Decrypt vault binary → JSON string. Raises ValueError on wrong passphrase or corruption."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(data) < 4 + 1 + 32 + 12 + 16:
        raise ValueError("Vault file too short — corrupted?")
    if data[:4] != VAULT_MAGIC:
        raise ValueError("Not a valid sslOpenCrypt vault file (bad magic bytes)")
    if data[4] != VAULT_VERSION:
        raise ValueError(f"Unsupported vault version: {data[4]}")

    salt       = data[5:37]
    nonce      = data[37:49]
    ciphertext = data[49:]

    key = _derive_key(passphrase, salt)
    aead = AESGCM(key)

    try:
        plaintext = aead.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Authentication failed — wrong passphrase or corrupted vault")

    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Vault lifecycle
# ---------------------------------------------------------------------------

def create_vault(passphrase: str) -> None:
    """
    Create a new, empty vault encrypted with the given passphrase.
    Overwrites any existing vault file.
    """
    global _vault_data, _vault_passphrase
    _vault_data = {"version": VAULT_VERSION, "entries": []}
    _vault_passphrase = passphrase
    _save()
    log_operation("vault", "create_vault", "", True)


def unlock_vault(passphrase: str) -> None:
    """
    Decrypt the vault file and load it into memory.
    Raises ValueError if passphrase is wrong or vault is corrupted.
    """
    global _vault_data, _vault_passphrase
    path = _vault_path()
    if not path.exists():
        raise FileNotFoundError("No vault found. Create one first.")
    with open(path, "rb") as f:
        data = f.read()
    payload_json = _decrypt_payload(data, passphrase)
    _vault_data = json.loads(payload_json)
    _vault_passphrase = passphrase
    log_operation("vault", "unlock_vault", "", True)


def lock_vault() -> None:
    """Clear in-memory vault state."""
    global _vault_data, _vault_passphrase
    _vault_data = None
    _vault_passphrase = None
    log_operation("vault", "lock_vault", "", True)


def _save() -> None:
    """Encrypt and write vault to disk."""
    if _vault_data is None or _vault_passphrase is None:
        raise RuntimeError("Vault is not unlocked")
    payload_json = json.dumps(_vault_data, ensure_ascii=False, indent=2)
    blob = _encrypt_payload(payload_json, _vault_passphrase)
    path = _vault_path()
    path.write_bytes(blob)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600


def _assert_unlocked():
    if _vault_data is None:
        raise RuntimeError("Vault is locked. Call unlock_vault() first.")


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------

def add_key(
    name: str,
    algorithm: str,
    pem: str,
    tags: list[str] | None = None,
    comment: str = "",
) -> str:
    """
    Add a private key to the vault. Returns the new entry ID (UUID4).
    pem: PEM-encoded private key string.
    """
    _assert_unlocked()
    entry_id = str(uuid.uuid4())
    entry: dict[str, Any] = {
        "id":         entry_id,
        "name":       name.strip(),
        "algorithm":  algorithm,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "pem":        pem.strip(),
        "tags":       list(tags or []),
        "comment":    comment.strip(),
    }
    _vault_data["entries"].append(entry)
    _save()
    log_operation("vault", f"add_key:{name}:{algorithm}", "", True)
    return entry_id


def remove_key(entry_id: str) -> None:
    """Remove a key entry by ID."""
    _assert_unlocked()
    before = len(_vault_data["entries"])
    _vault_data["entries"] = [e for e in _vault_data["entries"] if e["id"] != entry_id]
    if len(_vault_data["entries"]) == before:
        raise KeyError(f"Entry '{entry_id}' not found in vault")
    _save()
    log_operation("vault", f"remove_key:{entry_id}", "", True)


def list_keys() -> list[dict]:
    """
    Return a list of key metadata (no PEM content).
    Each dict: {id, name, algorithm, created_at, tags, comment}
    """
    _assert_unlocked()
    return [
        {k: v for k, v in e.items() if k != "pem"}
        for e in _vault_data["entries"]
    ]


def get_key_pem(entry_id: str) -> str:
    """Return the PEM content for a specific entry."""
    _assert_unlocked()
    for e in _vault_data["entries"]:
        if e["id"] == entry_id:
            return e["pem"]
    raise KeyError(f"Entry '{entry_id}' not found in vault")


def export_key_to_file(entry_id: str, output_path: str) -> None:
    """
    Write the private key PEM to a file with 0o600 permissions.
    The caller is responsible for deleting the file when done.
    """
    pem = get_key_pem(entry_id)
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(pem)
    os.chmod(output_path, stat.S_IRUSR | stat.S_IWUSR)
    log_operation("vault", f"export_key:{entry_id}", f"export to {output_path}", True)


def import_key_from_file(
    file_path: str,
    name: str,
    algorithm: str,
    tags: list[str] | None = None,
    comment: str = "",
) -> str:
    """Read a PEM file and add it to the vault. Returns entry ID."""
    with open(file_path, "r") as f:
        pem = f.read()
    return add_key(name, algorithm, pem, tags, comment)


def update_key_metadata(
    entry_id: str,
    name: str | None = None,
    tags: list[str] | None = None,
    comment: str | None = None,
) -> None:
    """Update name, tags, or comment for an existing entry."""
    _assert_unlocked()
    for e in _vault_data["entries"]:
        if e["id"] == entry_id:
            if name is not None:
                e["name"] = name.strip()
            if tags is not None:
                e["tags"] = list(tags)
            if comment is not None:
                e["comment"] = comment.strip()
            _save()
            log_operation("vault", f"update_key_metadata:{entry_id}", "", True)
            return
    raise KeyError(f"Entry '{entry_id}' not found in vault")


def change_passphrase(old_passphrase: str, new_passphrase: str) -> None:
    """
    Re-encrypt the vault with a new master passphrase.
    Verifies the old passphrase by attempting to decrypt first.
    """
    global _vault_passphrase
    _assert_unlocked()
    # Verify old passphrase matches current
    if old_passphrase != _vault_passphrase:
        raise ValueError("Current passphrase is incorrect")
    _vault_passphrase = new_passphrase
    _save()
    log_operation("vault", "change_passphrase", "", True)


def vault_stats() -> dict:
    """Return summary statistics about the vault."""
    _assert_unlocked()
    entries = _vault_data.get("entries", [])
    alg_counts: dict[str, int] = {}
    for e in entries:
        alg = e.get("algorithm", "Unknown")
        alg_counts[alg] = alg_counts.get(alg, 0) + 1
    return {
        "total_keys": len(entries),
        "algorithms": alg_counts,
        "vault_path": str(_vault_path()),
        "vault_size_bytes": _vault_path().stat().st_size if _vault_path().exists() else 0,
    }
