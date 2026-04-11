"""
modules/random/controller.py — Module 7: Secure Random Number & Password Generator

Operations:
  - random_bytes: generate N random bytes (hex, base64, or binary)
  - random_password: generate a random password
  - random_uuid: generate a random UUID v4
  - random_prime: generate a random prime number
  - dhparam: generate Diffie-Hellman parameters
  - entropy_estimate: estimate entropy in bits for a given output
"""

import math
import re
import string
import uuid

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult


def random_bytes(
    count: int,
    output_format: str = "hex",  # "hex" | "base64" | "binary_file"
    output_path: str | None = None,
) -> ExecutionResult:
    """
    Generate cryptographically strong random bytes.
    Uses openssl rand.
    """
    if output_format == "hex":
        cmd = ["rand", "-hex", str(count)]
    elif output_format == "base64":
        cmd = ["rand", "-base64", str(count)]
    elif output_format == "binary_file" and output_path:
        cmd = ["rand", "-out", output_path, str(count)]
    else:
        cmd = ["rand", "-hex", str(count)]

    r = run_openssl(cmd)
    if r.success:
        r.parsed["bytes"] = count
        r.parsed["format"] = output_format
        r.parsed["value"] = r.stdout.strip()
        r.parsed["entropy_bits"] = count * 8

    log_operation("random", f"random_bytes:{count}:{output_format}", r.command_str, r.success)
    return r


def random_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = True,
) -> ExecutionResult:
    """
    Generate a random password using the OS CSPRNG via openssl rand.
    The password is assembled from the raw bytes mod the character set size.
    """
    charset = ""
    if use_upper:
        charset += string.ascii_uppercase
    if use_lower:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if exclude_ambiguous:
        for ch in "Il1O0|`:;'\"":
            charset = charset.replace(ch, "")

    if not charset:
        charset = string.ascii_letters + string.digits

    # Get enough random bytes (4x length to ensure sufficient pool after modulo bias rejection)
    needed = length * 4
    r = run_openssl(["rand", "-hex", str(needed)])
    if not r.success:
        return r

    raw_hex = r.stdout.strip().replace("\n", "")
    raw_bytes = bytes.fromhex(raw_hex)

    # Rejection sampling to avoid modulo bias
    n = len(charset)
    password_chars = []
    for b in raw_bytes:
        if b < (256 - 256 % n):
            password_chars.append(charset[b % n])
        if len(password_chars) >= length:
            break

    password = "".join(password_chars[:length])
    r.parsed["password"] = password
    r.parsed["length"] = length
    r.parsed["charset_size"] = len(charset)
    r.parsed["entropy_bits"] = round(length * math.log2(len(charset)), 1)

    log_operation("random", f"random_password:len={length}", r.command_str, r.success)
    return r


def random_uuid() -> ExecutionResult:
    """Generate a UUID v4 using the system CSPRNG (Python uuid4 backed by os.urandom)."""
    uid = str(uuid.uuid4())
    r = run_openssl(["rand", "-hex", "16"])
    if r.success:
        hex_val = r.stdout.strip().replace("\n", "")
        # Format as UUID v4
        uid = f"{hex_val[0:8]}-{hex_val[8:12]}-4{hex_val[13:16]}-{hex_val[16:20]}-{hex_val[20:32]}"
        r.parsed["uuid"] = uid
        r.parsed["version"] = 4
    return r


def random_prime(bits: int = 512) -> ExecutionResult:
    """Generate a random prime number of the specified bit length."""
    cmd = ["prime", "-generate", "-bits", str(bits)]
    r = run_openssl(cmd)
    if r.success:
        r.parsed["prime"] = r.stdout.strip()
        r.parsed["bits"] = bits
    log_operation("random", f"random_prime:{bits}bits", r.command_str, r.success)
    return r


def dhparam(bits: int = 2048, output_path: str | None = None) -> ExecutionResult:
    """
    Generate Diffie-Hellman parameters.
    Warning: 2048-bit generation can take 1–5 minutes.
    """
    cmd = ["dhparam", str(bits)]
    if output_path:
        cmd += ["-out", output_path]
    r = run_openssl(cmd, timeout=600)
    if r.success:
        r.parsed["bits"] = bits
        r.parsed["output_path"] = output_path
    log_operation("random", f"dhparam:{bits}bits", r.command_str, r.success)
    return r


def entropy_estimate(value: str, assumed_charset_size: int | None = None) -> dict:
    """
    Estimate the entropy of a given value in bits.
    For hex strings: each nibble = 4 bits.
    For base64: each char ≈ 6 bits.
    For passwords: log2(charset_size) * length.
    """
    if not value:
        return {"entropy_bits": 0, "length": 0}

    length = len(value)
    # Try to detect format
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        # Hex
        bits_per_char = 4.0
        charset = "hex"
    elif re.fullmatch(r"[A-Za-z0-9+/]+=*", value):
        # Base64
        bits_per_char = 6.0
        charset = "base64"
    elif assumed_charset_size:
        bits_per_char = math.log2(assumed_charset_size)
        charset = f"custom({assumed_charset_size})"
    else:
        # Count unique characters as charset estimate
        unique = len(set(value))
        bits_per_char = math.log2(max(unique, 2))
        charset = f"estimated({unique} unique chars)"

    return {
        "entropy_bits": round(bits_per_char * length, 1),
        "bits_per_char": bits_per_char,
        "length": length,
        "charset": charset,
    }
