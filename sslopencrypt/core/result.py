"""
core/result.py — Structured result type returned by every Execution Layer call.

Every openssl/gpg subprocess invocation returns an ExecutionResult containing:
  - command: the exact command list that was run
  - command_str: the command as a displayable string (with sensitive args masked)
  - stdout: raw stdout bytes decoded to str
  - stderr: raw stderr bytes decoded to str
  - parsed: a Python dict of parsed/extracted fields (algorithm, key size, fingerprint…)
  - success: bool
  - exit_code: int
  - is_deprecated_alg: bool — True if the operation used a deprecated algorithm
  - deprecated_alg_name: str — name of the deprecated algorithm if applicable
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExecutionResult:
    command: list[str]
    command_str: str          # Display-safe version (passphrase replaced with [PASSPHRASE])
    stdout: str
    stderr: str
    parsed: dict
    success: bool
    exit_code: int
    is_deprecated_alg: bool = False
    deprecated_alg_name: str = ""

    @property
    def output(self) -> str:
        """Combined stdout + stderr for display."""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(self.stderr.strip())
        return "\n".join(parts)

    @property
    def error_message(self) -> str:
        """Human-readable error derived from stderr."""
        if self.success:
            return ""
        return self.stderr.strip() or f"Command failed with exit code {self.exit_code}"


DEPRECATED_ALGORITHMS = {
    "md5":   "MD5 is cryptographically broken — collision attacks are publicly known. Use SHA-256 or stronger.",
    "sha1":  "SHA-1 is deprecated — collision attacks (SHAttered) are publicly known. Use SHA-256 or stronger.",
    "rc4":   "RC4 is prohibited by RFC 7465 in TLS contexts and is cryptographically weak.",
    "3des":  "Triple DES (3DES) is deprecated — SWEET32 birthday attack applies. Use AES-256.",
    "des":   "Single DES is completely broken — 56-bit key can be brute-forced in hours.",
    "md4":   "MD4 is broken. Use SHA-256 or stronger.",
    "rc2":   "RC2 is a legacy cipher with known weaknesses. Use AES-256.",
}
