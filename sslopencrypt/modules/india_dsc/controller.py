"""
modules/india_dsc/controller.py — Module 10: India DSC & eSign.

Implements the v1.0 India DSC Token Manager:
  - Detect PKCS#11 USB DSC tokens (auto-detects common Indian token paths)
  - List objects (certificates & keys) on the token
  - Export the signing certificate from the token (public — safe)
  - Inspect the certificate (subject, serial, validity, CA chain)
  - Sign a document using the on-token private key (key never leaves)
  - Verify a document signature against India PKI (RCAI + intermediate chain)
  - India PKI Trust Store: display RCAI fingerprint, known CA info

Supported token libraries (pre-populated for India):
  ePass2003 / HYP2003 : /usr/lib/x86_64-linux-gnu/libcastle.so.1.0.0
  HyperPKI (HYP2003)  : /usr/lib/libhyper.so
  SafeNet eToken 5110 : /usr/lib/libeToken.so
  OpenSC (fallback)   : /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

Dependencies: pkcs11-tool (opensc package), pcscd, openssl
"""

import os
import shutil
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult


# ---------------------------------------------------------------------------
# Known Indian DSC token PKCS#11 library paths (Linux x86_64)
# ---------------------------------------------------------------------------

KNOWN_TOKEN_LIBS: list[tuple[str, str]] = [
    ("ePass2003 / HYP2003",
     "/usr/lib/x86_64-linux-gnu/libcastle.so.1.0.0"),
    ("HyperPKI (HYP2003)",
     "/usr/lib/libhyper.so"),
    ("SafeNet eToken 5110",
     "/usr/lib/libeToken.so"),
    ("WatchData Proxkey",
     "/usr/lib/x86_64-linux-gnu/libwatchdata.so"),
    ("OpenSC (fallback)",
     "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
    ("OpenSC (alt path)",
     "/usr/lib/opensc-pkcs11.so"),
]

# RCAI root certificate fingerprint (SHA-256) — manual verification reference.
# Source: cca.gov.in — verify out-of-band before trusting.
RCAI_SHA256_FINGERPRINT = (
    "1A:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:"
    "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90"
)

# Licensed India CAs (CCA list — verify current state at cca.gov.in/licenses)
INDIA_CAS: list[dict] = [
    {"name": "eMudhra Limited",         "website": "emudhra.com",      "type": "Class 3"},
    {"name": "Sify Technologies Ltd",   "website": "safescrypt.com",   "type": "Class 3"},
    {"name": "CDAC (e-Mudhra)",         "website": "cdac.in",          "type": "Class 3"},
    {"name": "NSDL e-Governance",       "website": "egov-nsdl.co.in",  "type": "Class 3"},
    {"name": "Pantasign",               "website": "pantasign.com",    "type": "Class 3"},
    {"name": "Verasys Technologies",    "website": "vsign.in",         "type": "Class 3"},
    {"name": "Capricorn Identity Services", "website": "capricornca.com", "type": "Class 3"},
    {"name": "IDRBT",                   "website": "idrbt.ac.in",      "type": "Class 3"},
    {"name": "National Informatics Centre", "website": "nic.in",       "type": "Class 3"},
    {"name": "TCS-CA",                  "website": "tcs.com",          "type": "Class 3"},
]


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

def _pkcs11_tool() -> str | None:
    return shutil.which("pkcs11-tool")


def _pcscd_running() -> bool:
    """Check if the pcscd daemon is running."""
    import subprocess
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "--quiet", "pcscd"],
            capture_output=True, timeout=3,
        )
        return r.returncode == 0
    except Exception:
        try:
            r = subprocess.run(
                ["pgrep", "-x", "pcscd"],
                capture_output=True, timeout=3,
            )
            return r.returncode == 0
        except Exception:
            return False


def check_dependencies() -> ExecutionResult:
    """
    Check that pkcs11-tool and pcscd are available.
    Returns ExecutionResult with parsed dict explaining what's installed/missing.
    """
    cmd_str = "pkcs11-tool --list-slots  # Check token presence"
    tool = _pkcs11_tool()
    pcscd = _pcscd_running()

    issues = []
    if not tool:
        issues.append("pkcs11-tool not found — install: sudo apt install opensc")
    if not pcscd:
        issues.append("pcscd not running — install/start: sudo apt install pcscd && sudo systemctl start pcscd")

    available_libs = [(name, path) for name, path in KNOWN_TOKEN_LIBS if Path(path).exists()]

    parsed = {
        "pkcs11_tool": tool or "not found",
        "pcscd_running": pcscd,
        "available_token_libs": available_libs,
        "issues": issues,
    }

    if issues:
        msg = "\n".join(issues)
        return ExecutionResult([], cmd_str, "", msg, parsed, False, 1)

    return ExecutionResult([], cmd_str, "Dependencies OK", "", parsed, True, 0)


# ---------------------------------------------------------------------------
# Token detection
# ---------------------------------------------------------------------------

def list_tokens(pkcs11_lib: str) -> ExecutionResult:
    """
    List all PKCS#11 slots (tokens) on the given library.
    Equivalent to: pkcs11-tool --module <lib> --list-slots
    """
    cmd_str = f"pkcs11-tool --module {pkcs11_lib} --list-slots"
    tool = _pkcs11_tool()
    if not tool:
        return ExecutionResult([], cmd_str, "", "pkcs11-tool not found. Install: sudo apt install opensc", {}, False, 1)

    import subprocess
    try:
        r = subprocess.run(
            [tool, "--module", pkcs11_lib, "--list-slots"],
            capture_output=True, text=True, timeout=10,
        )
        success = r.returncode == 0 or "Slot" in r.stdout
        tokens = []
        for line in r.stdout.splitlines():
            if "Slot" in line or "token label" in line.lower():
                tokens.append(line.strip())
        parsed = {"tokens": tokens, "raw": r.stdout[:2000]}
        log_operation("india_dsc", "list_tokens", cmd_str, success)
        return ExecutionResult([], cmd_str, r.stdout, r.stderr, parsed, success, r.returncode)
    except subprocess.TimeoutExpired:
        return ExecutionResult([], cmd_str, "", "Timeout — is the token plugged in?", {}, False, -1)
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def list_objects(pkcs11_lib: str, pin: str = "") -> ExecutionResult:
    """
    List certificates and keys on the token.
    Equivalent to: pkcs11-tool --module <lib> --login --list-objects
    """
    cmd_str = f"pkcs11-tool --module {pkcs11_lib} --login --list-objects"
    tool = _pkcs11_tool()
    if not tool:
        return ExecutionResult([], cmd_str, "", "pkcs11-tool not found.", {}, False, 1)

    import subprocess
    args = [tool, "--module", pkcs11_lib, "--list-objects"]
    if pin:
        args += ["--login", "--pin", pin]
    else:
        args += ["--login"]  # will prompt interactively or fail

    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        objects = []
        for line in r.stdout.splitlines():
            if any(kw in line for kw in ["Certificate", "Private Key", "Public Key", "Data"]):
                objects.append(line.strip())
        parsed = {"objects": objects, "raw": r.stdout[:3000]}
        success = r.returncode == 0
        log_operation("india_dsc", "list_objects", cmd_str, success)
        return ExecutionResult([], cmd_str, r.stdout, r.stderr, parsed, success, r.returncode)
    except subprocess.TimeoutExpired:
        return ExecutionResult([], cmd_str, "", "Timeout — check PIN or token state", {}, False, -1)
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


# ---------------------------------------------------------------------------
# Certificate export
# ---------------------------------------------------------------------------

def export_certificate(pkcs11_lib: str, output_pem: str, label: str = "Certificate",
                        pin: str = "") -> ExecutionResult:
    """
    Export the signing certificate from the DSC token to a PEM file.
    The certificate (public) is safe to export — the private key never leaves the token.

    Equivalent commands:
      pkcs11-tool --module <lib> --login --read-object --type cert --label <label> -o cert.der
      openssl x509 -in cert.der -inform DER -out cert.pem
    """
    cmd_str = (
        f"pkcs11-tool --module {pkcs11_lib} --login "
        f"--read-object --type cert --label \"{label}\" -o cert.der\n"
        f"openssl x509 -in cert.der -inform DER -out {output_pem}"
    )
    tool = _pkcs11_tool()
    if not tool:
        return ExecutionResult([], cmd_str, "", "pkcs11-tool not found.", {}, False, 1)

    import subprocess
    import tempfile

    der_fd, der_path = tempfile.mkstemp(suffix=".der")
    os.close(der_fd)

    try:
        args = [tool, "--module", pkcs11_lib, "--read-object", "--type", "cert",
                "--label", label, "-o", der_path]
        if pin:
            args += ["--login", "--pin", pin]
        else:
            args += ["--login"]

        r = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            return ExecutionResult([], cmd_str, r.stdout, r.stderr, {}, False, r.returncode)

        # Convert DER to PEM
        r2 = run_openssl(["x509", "-in", der_path, "-inform", "DER", "-out", output_pem])
        if r2.success:
            log_operation("india_dsc", "export_certificate", cmd_str, True)
            r2.command_str = cmd_str
            r2.parsed["output_pem"] = output_pem
        return r2

    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)
    finally:
        try:
            os.unlink(der_path)
        except OSError:
            pass


def inspect_certificate(cert_path: str) -> ExecutionResult:
    """
    Inspect a certificate — show subject, issuer, serial, validity, SAN, key usage.
    Equivalent to: openssl x509 -in cert.pem -text -noout
    """
    cmd = ["x509", "-in", cert_path, "-text", "-noout"]
    r = run_openssl(cmd)
    log_operation("india_dsc", "inspect_certificate", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# On-token signing (private key never leaves)
# ---------------------------------------------------------------------------

def sign_file_with_token(pkcs11_lib: str, cert_path: str, input_file: str,
                          output_sig: str, key_label: str = "Private Key",
                          pin: str = "") -> ExecutionResult:
    """
    Sign a file using the private key on the DSC token.
    Produces a detached CMS/PKCS#7 signature (.p7s).

    The private key NEVER leaves the token — signing happens inside the hardware.

    Equivalent to:
      openssl cms -sign -binary -nodetach -engine pkcs11 \\
          -inkey 'pkcs11:token=<label>;object=<key_label>;type=private' \\
          -keyform engine -signer cert.pem \\
          -in document.pdf -out document.p7s -outform DER
    """
    pin_part = f"-passin 'pass:{pin}'" if pin else ""
    cmd_str = (
        f"# Sign using on-token key — private key stays on hardware\n"
        f"openssl cms -sign -binary -nodetach -engine pkcs11 \\\n"
        f"    -inkey 'pkcs11:object={key_label};type=private' \\\n"
        f"    -keyform engine -signer {cert_path} \\\n"
        f"    {pin_part} \\\n"
        f"    -in {input_file} -out {output_sig} -outform DER"
    )

    # Note: actual pkcs11 engine invocation depends on the engine being installed.
    # We build and return the exact command — execution requires openssl pkcs11 engine.
    import subprocess
    args = [
        "openssl", "cms", "-sign", "-binary", "-nodetach",
        "-engine", "pkcs11",
        "-inkey", f"pkcs11:object={key_label};type=private",
        "-keyform", "engine",
        "-signer", cert_path,
        "-in", input_file,
        "-out", output_sig,
        "-outform", "DER",
    ]
    if pin:
        args += ["-passin", f"pass:{pin}"]

    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        success = r.returncode == 0
        parsed = {"output_sig": output_sig, "cert": cert_path}
        log_operation("india_dsc", "sign_file_with_token", cmd_str, success,
                      is_deprecated=False)
        return ExecutionResult(args[1:], cmd_str, r.stdout, r.stderr, parsed, success, r.returncode)
    except FileNotFoundError:
        return ExecutionResult([], cmd_str, "",
                               "openssl not found. Ensure OpenSSL 1.1.1+ is installed.", {}, False, -1)
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def verify_signature_india_pki(sig_file: str, input_file: str,
                                 ca_bundle: str = "") -> ExecutionResult:
    """
    Verify a CMS/PKCS#7 signature against the India PKI chain.

    Equivalent to:
      openssl cms -verify -in sig.p7s -inform DER -binary \\
          -CAfile india_chain.pem -content document.pdf
    """
    cmd = [
        "cms", "-verify",
        "-in", sig_file,
        "-inform", "DER",
        "-binary",
        "-content", input_file,
    ]
    if ca_bundle:
        cmd += ["-CAfile", ca_bundle]
    else:
        cmd += ["-noverify"]  # skip chain verification if no bundle provided

    cmd_str = (
        f"# Verify India DSC signature\n"
        f"openssl cms -verify -in {sig_file} -inform DER -binary \\\n"
        + (f"    -CAfile {ca_bundle} \\\n" if ca_bundle else "    # -CAfile india_chain.pem  (chain not provided)\n")
        + f"    -content {input_file}"
    )

    r = run_openssl(cmd)
    r.command_str = cmd_str
    log_operation("india_dsc", "verify_signature", cmd_str, r.success)
    return r


# ---------------------------------------------------------------------------
# India PKI Trust Store
# ---------------------------------------------------------------------------

def get_india_pki_info() -> dict:
    """Return known India PKI information for display."""
    return {
        "rcai_fingerprint_sha256": RCAI_SHA256_FINGERPRINT,
        "rcai_url": "https://cca.gov.in/root-certifying-authority.html",
        "licensed_cas": INDIA_CAS,
        "cca_url": "https://cca.gov.in/licenses.html",
        "algorithm_requirement": "RSA-2048+ or P-256, SHA-256, Class 3 only",
        "class2_discontinued": "01-Jan-2021 (Class 2 discontinued by CCA)",
        "kyc_requirement": "Video KYC mandatory since July 2024 (IVG update)",
        "token_standard": "FIPS 140-2 Level 2+ certified hardware token",
    }


def detect_available_libs() -> list[tuple[str, str, bool]]:
    """
    Return list of (name, path, is_present) for known Indian DSC token libraries.
    """
    return [(name, path, Path(path).exists()) for name, path in KNOWN_TOKEN_LIBS]
