"""
core/executor.py — Secure subprocess wrapper for openssl and gpg2.

Spec requirements:
  - All subprocess calls sanitise arguments; no shell=True anywhere.
  - openssl invoked with explicit path; binary hash verified at startup.
  - Returns ExecutionResult with command shown, stdout, stderr, parsed output, success flag.
  - Deprecated algorithms produce is_deprecated_alg=True in the result.

Windows builds bundle openssl.exe inside the PyInstaller payload (see
packaging/sslopencrypt.spec) so end users do not have to install OpenSSL
themselves. The bundled copy always wins over anything on PATH, and its
SHA-256 is checked against packaging/openssl_manifest.json before first use.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from functools import lru_cache
from typing import Optional

from .result import ExecutionResult, DEPRECATED_ALGORITHMS


# ---------------------------------------------------------------------------
# Binary discovery and verification
# ---------------------------------------------------------------------------

_OPENSSL_PATH: str | None = None
_GPG_PATH: str | None = None

_INSTALL_HINT = {
    "win32": "OpenSSL was not found and this build has no bundled copy. "
             "Reinstall sslOpenCrypt, or install Win64 OpenSSL and add it to PATH.",
    "darwin": "openssl binary not found. Install OpenSSL: brew install openssl",
}
_INSTALL_HINT_DEFAULT = "openssl binary not found. Install OpenSSL: sudo apt install openssl"


def _find_binary(name: str) -> str | None:
    path = shutil.which(name)
    if path and os.access(path, os.X_OK):
        return path
    return None


def bundle_dir() -> str | None:
    """Directory holding bundled binaries, or None when running from source.

    sys._MEIPASS is set by the PyInstaller bootloader for both onefile (a
    temporary extraction directory) and onedir (the _internal/ folder).
    """
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", None)
    return None


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_bundled_binary(path: str) -> None:
    """Check a bundled binary against the manifest recorded at build time.

    A missing manifest is tolerated (older builds); a manifest that disagrees
    with the binary on disk is fatal — that is either corruption or tampering,
    and a crypto tool must not shell out to an unverified openssl.
    """
    base = bundle_dir()
    if not base:
        return
    manifest_path = os.path.join(base, "openssl_manifest.json")
    if not os.path.isfile(manifest_path):
        return
    try:
        with open(manifest_path, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Bundled openssl manifest is unreadable: {exc}") from exc

    expected = manifest.get(os.path.basename(path))
    if not expected:
        return
    actual = _sha256(path)
    if actual != expected:
        raise RuntimeError(
            f"Bundled {os.path.basename(path)} failed its integrity check.\n"
            f"  expected SHA-256: {expected}\n"
            f"  actual   SHA-256: {actual}\n"
            "Refusing to run. Re-download sslOpenCrypt from the official release page."
        )


def _bundled_openssl() -> str | None:
    """Path to the openssl shipped inside the frozen bundle, if present."""
    base = bundle_dir()
    if not base:
        return None
    name = "openssl.exe" if sys.platform == "win32" else "openssl"
    candidate = os.path.join(base, name)
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


@lru_cache(maxsize=1)
def get_openssl_path() -> str:
    global _OPENSSL_PATH
    if _OPENSSL_PATH:
        return _OPENSSL_PATH

    # A bundled openssl always wins — it is the version this build was tested
    # against, and on Windows it is usually the only one present.
    bundled = _bundled_openssl()
    if bundled:
        _verify_bundled_binary(bundled)
        _OPENSSL_PATH = bundled
        return bundled

    if sys.platform == "win32":
        candidates = [
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files\OpenSSL\bin\openssl.exe",
        ]
    else:
        candidates = ["/usr/bin/openssl", "/usr/local/bin/openssl", "/opt/homebrew/bin/openssl"]
    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            _OPENSSL_PATH = candidate
            return candidate
    found = _find_binary("openssl")
    if found:
        _OPENSSL_PATH = found
        return found
    raise FileNotFoundError(_INSTALL_HINT.get(sys.platform, _INSTALL_HINT_DEFAULT))


def openssl_is_bundled() -> bool:
    """True when the openssl in use ships with this build."""
    bundled = _bundled_openssl()
    return bool(bundled and get_openssl_path() == bundled)


def _bundled_openssl_env() -> dict:
    """Environment overrides needed by the bundled openssl.

    A prebuilt openssl.exe has an OPENSSLDIR compiled in that points at the
    build machine's filesystem. Left alone it emits config warnings and looks
    for providers in a directory that does not exist on the user's PC, so both
    paths are redirected into the bundle. OPENSSL_CONF is only set when a
    config actually shipped — pointing it at a missing file is worse than
    leaving it unset.
    """
    base = bundle_dir()
    if not base:
        return {}
    env = {"OPENSSL_MODULES": base}
    cnf = os.path.join(base, "openssl.cnf")
    if os.path.isfile(cnf):
        env["OPENSSL_CONF"] = cnf
    return env


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
    env = _bundled_openssl_env() if openssl_is_bundled() else None
    return _run(binary, args, input_data=input_data, timeout=timeout, env=env)


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
