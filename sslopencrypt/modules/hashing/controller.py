"""
modules/hashing/controller.py — Module 3: Hashing & Message Digests

Operations:
  - hash_file: compute hash of a file
  - hash_text: compute hash of a text string
  - hmac_file: HMAC of a file with a key
  - verify_hash: compare computed vs reference hash
  - batch_hash: hash all files in a directory
"""

import os
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult

# Safe defaults
BEGINNER_ALGORITHMS = ["SHA-256", "SHA-512"]

# All algorithms
ALL_ALGORITHMS = [
    "SHA-256", "SHA-384", "SHA-512",
    "SHA3-256", "SHA3-384", "SHA3-512",
    "SHA3-224",
    "BLAKE2b512", "BLAKE2s256",
    # Deprecated — warning shown
    "SHA-1", "MD5",
]

_DEPRECATED = {"SHA-1", "MD5"}

_ALG_TO_OPENSSL = {
    "SHA-256":    "sha256",
    "SHA-384":    "sha384",
    "SHA-512":    "sha512",
    "SHA3-224":   "sha3-224",
    "SHA3-256":   "sha3-256",
    "SHA3-384":   "sha3-384",
    "SHA3-512":   "sha3-512",
    "BLAKE2b512": "blake2b512",
    "BLAKE2s256": "blake2s256",
    "SHA-1":      "sha1",
    "MD5":        "md5",
}


def hash_file(file_path: str, algorithm: str = "SHA-256") -> ExecutionResult:
    """Compute the hash of a file."""
    openssl_alg = _ALG_TO_OPENSSL.get(algorithm.upper(), algorithm.lower())
    cmd = ["dgst", f"-{openssl_alg}", file_path]
    r = run_openssl(cmd)

    if r.success:
        # Parse "SHA256(file.txt)= abc123..."
        parts = r.stdout.strip().split("= ", 1)
        if len(parts) == 2:
            r.parsed["hash"] = parts[1].strip()
            r.parsed["algorithm"] = algorithm
            r.parsed["file"] = file_path

    log_operation(
        "hashing", f"hash_file:{algorithm}", r.command_str, r.success,
        is_deprecated=algorithm in _DEPRECATED,
        deprecated_alg=algorithm if algorithm in _DEPRECATED else "",
    )
    return r


def hash_text(text: str, algorithm: str = "SHA-256") -> ExecutionResult:
    """Compute hash of a text string."""
    openssl_alg = _ALG_TO_OPENSSL.get(algorithm.upper(), algorithm.lower())
    cmd = ["dgst", f"-{openssl_alg}"]
    r = run_openssl(cmd, input_data=text.encode("utf-8"))

    if r.success:
        parts = r.stdout.strip().split("= ", 1)
        if len(parts) == 2:
            r.parsed["hash"] = parts[1].strip()
        elif r.stdout.strip():
            r.parsed["hash"] = r.stdout.strip()
        r.parsed["algorithm"] = algorithm

    log_operation(
        "hashing", f"hash_text:{algorithm}", r.command_str, r.success,
        is_deprecated=algorithm in _DEPRECATED,
        deprecated_alg=algorithm if algorithm in _DEPRECATED else "",
    )
    return r


def hmac_file(file_path: str, key: str, algorithm: str = "SHA-256") -> ExecutionResult:
    """Compute HMAC of a file with a string key."""
    openssl_alg = _ALG_TO_OPENSSL.get(algorithm.upper(), algorithm.lower())
    cmd = ["dgst", f"-{openssl_alg}", "-hmac", key, file_path]
    r = run_openssl(cmd)

    if r.success:
        parts = r.stdout.strip().split("= ", 1)
        if len(parts) == 2:
            r.parsed["hmac"] = parts[1].strip()
            r.parsed["algorithm"] = f"HMAC-{algorithm}"

    log_operation("hashing", f"hmac_file:{algorithm}", r.command_str, r.success)
    return r


def hmac_text(text: str, key: str, algorithm: str = "SHA-256") -> ExecutionResult:
    """Compute HMAC of a text string."""
    openssl_alg = _ALG_TO_OPENSSL.get(algorithm.upper(), algorithm.lower())
    cmd = ["dgst", f"-{openssl_alg}", "-hmac", key]
    r = run_openssl(cmd, input_data=text.encode("utf-8"))

    if r.success:
        parts = r.stdout.strip().split("= ", 1)
        if len(parts) == 2:
            r.parsed["hmac"] = parts[1].strip()
        r.parsed["algorithm"] = f"HMAC-{algorithm}"

    log_operation("hashing", f"hmac_text:{algorithm}", r.command_str, r.success)
    return r


def verify_hash(file_path: str, reference_hash: str, algorithm: str = "SHA-256") -> ExecutionResult:
    """Verify a file against a reference hash. Returns parsed['match']=True/False."""
    r = hash_file(file_path, algorithm)
    if r.success:
        computed = r.parsed.get("hash", "")
        match = computed.lower().strip() == reference_hash.lower().strip()
        r.parsed["match"] = match
        r.parsed["reference_hash"] = reference_hash
        r.parsed["computed_hash"] = computed
    return r


def batch_hash(directory: str, algorithm: str = "SHA-256", recursive: bool = False) -> list[dict]:
    """Compute hashes for all files in a directory. Returns list of {file, hash, success}."""
    results = []
    base = Path(directory)
    pattern = "**/*" if recursive else "*"
    for fpath in sorted(base.glob(pattern)):
        if fpath.is_file():
            r = hash_file(str(fpath), algorithm)
            results.append({
                "file": str(fpath),
                "hash": r.parsed.get("hash", ""),
                "success": r.success,
                "algorithm": algorithm,
            })
    return results


def avalanche_demo(text: str, algorithm: str = "SHA-256") -> dict:
    """
    Avalanche effect demo: hash the original text, flip one bit, show the difference.
    Returns dict with original_hash, modified_hash, bits_changed.
    """
    r1 = hash_text(text, algorithm)
    # Flip the first character
    if not text:
        return {}
    modified = chr(ord(text[0]) ^ 1) + text[1:]
    r2 = hash_text(modified, algorithm)

    h1 = r1.parsed.get("hash", "")
    h2 = r2.parsed.get("hash", "")

    if h1 and h2:
        b1 = bin(int(h1, 16))[2:].zfill(len(h1) * 4)
        b2 = bin(int(h2, 16))[2:].zfill(len(h2) * 4)
        bits_changed = sum(c1 != c2 for c1, c2 in zip(b1, b2))
        total_bits = len(b1)
        return {
            "original_text": text,
            "modified_text": modified,
            "algorithm": algorithm,
            "original_hash": h1,
            "modified_hash": h2,
            "bits_changed": bits_changed,
            "total_bits": total_bits,
            "percent_changed": round(100 * bits_changed / total_bits, 1) if total_bits else 0,
        }
    return {}
