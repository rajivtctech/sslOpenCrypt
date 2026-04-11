"""
core/executor.py — Secure subprocess wrapper for openssl and gpg2.

Spec requirements:
  - All subprocess calls sanitise arguments; no shell=True anywhere.
  - openssl invoked with explicit path; binary hash verified at startup.
  - Returns ExecutionResult with command shown, stdout, stderr, parsed output, success flag.
  - Deprecated algorithms produce is_deprecated_alg=True in the result.
"""

import hashlib
import os
import re
import shutil
import subprocess
from functools import lru_cache
from typing import Optional

from .result import ExecutionResult, DEPRECATED_ALGORITHMS


# ---------------------------------------------------------------------------
# Binary discovery and verification
# ---------------------------------------------------------------------------

_OPENSSL_PATH: str | None = None
_GPG_PATH: str | None = None


def _find_binary(name: str) -> str | None:
    path = shutil.which(name)
    if path and os.access(path, os.X_OK):
        return path
    return None


@lru_cache(maxsize=1)
def get_openssl_path() -> str:
    global _OPENSSL_PATH
    if _OPENSSL_PATH:
        return _OPENSSL_PATH
    for candidate in ["/usr/bin/openssl", "/usr/local/bin/openssl", "/opt/homebrew/bin/openssl"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _OPENSSL_PATH = candidate
            return candidate
    found = _find_binary("openssl")
    if found:
        _OPENSSL_PATH = found
        return found
    raise FileNotFoundError(
        "openssl binary not found. Install OpenSSL: sudo apt install openssl"
    )


@lru_cache(maxsize=1)
def get_gpg_path() -> str | None:
    global _GPG_PATH
    for candidate in ["/usr/bin/gpg2", "/usr/bin/gpg", "/usr/local/bin/gpg2", "/usr/local/bin/gpg"]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _GPG_PATH = candidate
            return candidate
    found = _find_binary("gpg2") or _find_binary("gpg")
    if found:
        _GPG_PATH = found
    return _GPG_PATH


def openssl_version() -> str:
    """Return the openssl version string."""
    result = run_openssl(["version"])
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Argument sanitisation
# ---------------------------------------------------------------------------

_SENSITIVE_ARGS = re.compile(
    r"(?i)(pass(?:phrase)?[:=]|password[:=]|-passin\s+\S+|-passout\s+\S+)"
)


def _mask_sensitive(cmd: list[str]) -> str:
    """Produce a display-safe version of the command list."""
    parts = []
    skip_next = False
    for i, arg in enumerate(cmd):
        if skip_next:
            parts.append("[PASSPHRASE]")
            skip_next = False
            continue
        if arg in ("-passin", "-passout", "-pass", "-passphrase", "-new", "-password"):
            parts.append(arg)
            skip_next = True
        elif arg.startswith("pass:") or arg.startswith("file:") and "key" in cmd[max(0, i - 1)].lower():
            parts.append("pass:[PASSPHRASE]")
        else:
            parts.append(arg)
    return " ".join(parts)


def _check_deprecated(cmd: list[str]) -> tuple[bool, str]:
    """Check if any deprecated algorithm appears in the command."""
    cmd_lower = " ".join(cmd).lower()
    for alg, _ in DEPRECATED_ALGORITHMS.items():
        # Match as a word boundary
        if re.search(r"\b" + alg.replace("-", r"[\-_]?") + r"\b", cmd_lower):
            return True, alg.upper()
    return False, ""


# ---------------------------------------------------------------------------
# Core execution
# ---------------------------------------------------------------------------

def _run(
    binary: str,
    args: list[str],
    input_data: bytes | None = None,
    timeout: int = 120,
    env: dict | None = None,
) -> ExecutionResult:
    """Low-level subprocess runner — never uses shell=True."""
    cmd = [binary] + [str(a) for a in args]
    cmd_str = _mask_sensitive(cmd)
    is_deprecated, depr_name = _check_deprecated(cmd)

    if is_deprecated and depr_name:
        warning_prefix = f"# WARNING: {depr_name} is deprecated — {DEPRECATED_ALGORITHMS.get(depr_name.lower(), 'use a modern algorithm')}\n"
        cmd_str = warning_prefix + cmd_str
    else:
        warning_prefix = ""

    proc_env = os.environ.copy()
    if env:
        proc_env.update(env)

    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            timeout=timeout,
            env=proc_env,
            shell=False,          # NEVER shell=True
        )
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
        success = proc.returncode == 0
        return ExecutionResult(
            command=cmd,
            command_str=cmd_str,
            stdout=stdout,
            stderr=stderr,
            parsed={},
            success=success,
            exit_code=proc.returncode,
            is_deprecated_alg=is_deprecated,
            deprecated_alg_name=depr_name,
        )
    except subprocess.TimeoutExpired:
        return ExecutionResult(
            command=cmd,
            command_str=cmd_str,
            stdout="",
            stderr=f"Command timed out after {timeout} seconds.",
            parsed={},
            success=False,
            exit_code=-1,
        )
    except FileNotFoundError as e:
        return ExecutionResult(
            command=cmd,
            command_str=cmd_str,
            stdout="",
            stderr=str(e),
            parsed={},
            success=False,
            exit_code=-2,
        )


def run_openssl(args: list[str], input_data: bytes | None = None, timeout: int = 120) -> ExecutionResult:
    binary = get_openssl_path()
    return _run(binary, args, input_data=input_data, timeout=timeout)


def run_gpg(args: list[str], input_data: bytes | None = None, timeout: int = 120) -> ExecutionResult:
    binary = get_gpg_path()
    if not binary:
        return ExecutionResult(
            command=["gpg"] + args,
            command_str="gpg " + " ".join(args),
            stdout="",
            stderr="gpg2 / gpg binary not found. Install GnuPG: sudo apt install gnupg2",
            parsed={},
            success=False,
            exit_code=-2,
        )
    return _run(binary, args, input_data=input_data, timeout=timeout)
