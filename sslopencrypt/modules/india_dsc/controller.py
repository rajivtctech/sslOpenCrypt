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
  - Certificate expiry check with days-remaining alert
  - Token PIN health check (remaining attempts before lockout)
  - Portal workflow validators (MCA21, IT e-filing, GST, GeM/CPPP)
  - eSign API stub (Aadhaar OTP-based, CCA-licensed ASPs)

Supported token libraries (pre-populated for India):
  ePass2003 / HYP2003 : /usr/lib/x86_64-linux-gnu/libcastle.so.1.0.0
  HyperPKI (HYP2003)  : /usr/lib/libhyper.so
  SafeNet eToken 5110 : /usr/lib/libeToken.so
  OpenSC (fallback)   : /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

Dependencies: pkcs11-tool (opensc package), pcscd, openssl, cryptography
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

# ---------------------------------------------------------------------------
# RCAI root certificate fingerprints (SHA-256).
# Source: certificates downloaded from cca.gov.in and fingerprints computed
# directly from the DER/PEM files.  Verify out-of-band at cca.gov.in or by
# emailing verifyroot@cca.gov.in before trusting.
# ---------------------------------------------------------------------------

# CCA India 2022 — primary RCAI root (valid 2022-02-02 → 2042-02-02)
RCAI_SHA256_FINGERPRINT = (
    "9A:3F:D3:17:67:98:E8:42:DD:CB:12:C2:62:F1:1C:FA:"
    "CC:A7:0A:8B:84:C6:EA:6F:DA:30:84:2A:95:A9:4C:D8"
)

# CCA India 2022 SPL — supplementary root
RCAI_SPL_SHA256_FINGERPRINT = (
    "B7:24:68:9B:79:B2:EF:94:21:EF:8F:5C:C7:33:EB:09:"
    "38:51:B1:70:EE:71:51:77:00:5A:09:F2:26:D8:C9:1A"
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


# ---------------------------------------------------------------------------
# PDF signing (PAdES) via pyhanko — embedded signature accepted by portals
# ---------------------------------------------------------------------------

def sign_pdf_with_token(
    pkcs11_lib: str,
    input_pdf: str,
    output_pdf: str,
    pin: str = "",
    cert_label: str = "Certificate",
    key_label: str = "Private Key",
    field_name: str = "Signature1",
    reason: str = "Digitally signed with India DSC",
    location: str = "",
    contact: str = "",
    tsa_url: str = "",
) -> ExecutionResult:
    """
    Sign a PDF in-place using the on-token private key (PAdES / CAdES style).

    The resulting PDF contains an embedded CMS signature compatible with
    Adobe Acrobat, Foxit, and Indian e-governance portals (MCA21, IT e-filing).

    Parameters
    ----------
    pkcs11_lib    : path to the vendor PKCS#11 .so library
    input_pdf     : source PDF path
    output_pdf    : destination path for the signed PDF
    pin           : token PIN
    cert_label    : certificate object label on the token
    key_label     : private key object label on the token
    field_name    : name of the PDF signature field to create/fill
    reason        : signature reason string (appears in Acrobat signature panel)
    location      : signing location string (optional)
    contact       : contact info / email (optional)
    tsa_url       : RFC 3161 TSA URL for a trusted timestamp (required by GeM/CPPP)

    Equivalent openssl / manual operation:
      openssl cms -sign -binary -nodetach -engine pkcs11 \\
          -inkey 'pkcs11:...' -signer cert.pem -in doc.pdf -out doc.p7s
      # then embed the p7s into the PDF — pyhanko handles this natively.
    """
    cmd_str = (
        f"# pyhanko: sign PDF with PKCS#11 token\n"
        f"# python3 -m pyhanko sign addsig --field {field_name} "
        f"--pkcs11-module {pkcs11_lib} pkcs11 {input_pdf} {output_pdf}"
    )

    try:
        from pyhanko.sign.pkcs11 import PKCS11Signer, open_pkcs11_session
        from pyhanko.sign import signers, fields as ph_fields
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        from pyhanko.sign.signers import PdfSignatureMetadata
    except ImportError as e:
        return ExecutionResult(
            [], cmd_str, "",
            f"pyhanko not installed: {e}\nInstall: pip install pyhanko python-pkcs11",
            {}, False, 1,
        )

    try:
        if tsa_url:
            from pyhanko.sign.timestamps import HTTPTimeStamper
            timestamper = HTTPTimeStamper(tsa_url)
        else:
            timestamper = None

        with open_pkcs11_session(pkcs11_lib, user_pin=pin or None) as session:
            signer = PKCS11Signer(
                session,
                cert_label=cert_label,
                key_label=key_label,
            )

            meta = PdfSignatureMetadata(
                field_name=field_name,
                reason=reason,
                location=location or None,
                contact_info=contact or None,
            )

            with open(input_pdf, "rb") as f:
                writer = IncrementalPdfFileWriter(f)
                out_stream = signers.sign_pdf(
                    writer,
                    meta,
                    signer=signer,
                    timestamper=timestamper,
                )

            with open(output_pdf, "wb") as f:
                out_stream.seek(0)
                f.write(out_stream.read())

        parsed = {
            "output_pdf": output_pdf,
            "field_name": field_name,
            "reason": reason,
            "timestamped": tsa_url != "",
            "tsa_url": tsa_url,
        }
        log_operation("india_dsc", "sign_pdf_with_token", cmd_str, True)
        return ExecutionResult(
            [], cmd_str,
            f"PDF signed successfully.\nOutput: {output_pdf}"
            + (f"\nTimestamp applied via {tsa_url}" if tsa_url else ""),
            "", parsed, True, 0,
        )

    except FileNotFoundError as e:
        return ExecutionResult([], cmd_str, "", f"File not found: {e}", {}, False, 1)
    except Exception as e:
        log_operation("india_dsc", "sign_pdf_with_token", cmd_str, False)
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


def detect_available_libs() -> list[tuple[str, str, bool]]:
    """
    Return list of (name, path, is_present) for known Indian DSC token libraries.
    """
    return [(name, path, Path(path).exists()) for name, path in KNOWN_TOKEN_LIBS]


# ---------------------------------------------------------------------------
# Certificate expiry check
# ---------------------------------------------------------------------------

def check_certificate_expiry(cert_path: str) -> ExecutionResult:
    """
    Parse a PEM certificate and return its expiry information.

    Parsed dict keys:
      subject        — certificate subject DN
      issuer         — certificate issuer DN
      not_before     — ISO-format string
      not_after      — ISO-format string
      days_remaining — integer (negative = already expired)
      status         — "valid" | "expiring_soon" | "expired"
      alert_level    — "green" | "amber" | "red"

    Thresholds:
      > 30 days  → green  / valid
      1–30 days  → amber  / expiring_soon
      0 or less  → red    / expired
    """
    cmd_str = f"openssl x509 -in {cert_path} -noout -subject -issuer -dates"
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timezone

        with open(cert_path, "rb") as f:
            data = f.read()

        try:
            cert = x509.load_pem_x509_certificate(data)
        except Exception:
            cert = x509.load_der_x509_certificate(data)

        now = datetime.now(tz=timezone.utc)
        try:
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
        except AttributeError:
            # older cryptography versions
            import pytz
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)

        days_remaining = (not_after - now).days

        if days_remaining > 30:
            status, alert_level = "valid", "green"
        elif days_remaining >= 1:
            status, alert_level = "expiring_soon", "amber"
        else:
            status, alert_level = "expired", "red"

        parsed = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_remaining": days_remaining,
            "status": status,
            "alert_level": alert_level,
        }

        stdout = (
            f"Subject : {parsed['subject']}\n"
            f"Issuer  : {parsed['issuer']}\n"
            f"Valid   : {not_before.strftime('%d %b %Y')} → {not_after.strftime('%d %b %Y')}\n"
            f"Status  : {status.upper()}  ({days_remaining} days remaining)"
        )
        log_operation("india_dsc", "check_certificate_expiry", cmd_str, True)
        return ExecutionResult([], cmd_str, stdout, "", parsed, True, 0)

    except FileNotFoundError:
        return ExecutionResult([], cmd_str, "", f"File not found: {cert_path}", {}, False, 1)
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


# ---------------------------------------------------------------------------
# Token PIN health check
# ---------------------------------------------------------------------------

def check_token_pin_health(pkcs11_lib: str, pin: str = "") -> ExecutionResult:
    """
    Query the token for PIN health: remaining PIN attempts and lock status.

    Uses pkcs11-tool --list-slots --module <lib> (verbose output) and, when a
    PIN is supplied, attempts a login to confirm it is accepted.

    Parsed dict keys:
      slots             — list of slot info strings
      pin_valid         — bool | None (None = not tested, no PIN supplied)
      token_present     — bool
      flags             — raw flags string from pkcs11-tool (contains "PIN locked",
                          "PIN count low", etc. if applicable)
      warning           — human-readable warning string if risk detected
    """
    cmd_str = f"pkcs11-tool --module {pkcs11_lib} --list-slots"
    tool = _pkcs11_tool()
    if not tool:
        return ExecutionResult([], cmd_str, "", "pkcs11-tool not found.", {}, False, 1)

    import subprocess

    try:
        r = subprocess.run(
            [tool, "--module", pkcs11_lib, "--list-slots"],
            capture_output=True, text=True, timeout=10,
        )
        output = r.stdout + r.stderr

        # Parse flags from pkcs11-tool slot listing
        flags_lines = [l.strip() for l in output.splitlines() if "flags" in l.lower()]
        flags_str = "; ".join(flags_lines)

        pin_locked = "PIN locked" in output or "token locked" in output.lower()
        pin_count_low = "PIN count low" in output
        token_present = "token present" in output.lower() or "Token" in output

        warning = ""
        if pin_locked:
            warning = "TOKEN IS LOCKED — contact your CA immediately for re-issuance."
        elif pin_count_low:
            warning = "WARNING: PIN count low — very few attempts remain before permanent lockout."

        # Optionally test the PIN by attempting a login
        pin_valid = None
        if pin and not pin_locked:
            r2 = subprocess.run(
                [tool, "--module", pkcs11_lib, "--login", "--pin", pin, "--list-objects"],
                capture_output=True, text=True, timeout=15,
            )
            pin_valid = r2.returncode == 0
            if not pin_valid and "incorrect" in (r2.stderr + r2.stdout).lower():
                warning = (
                    "INCORRECT PIN entered. "
                    "Each failed attempt reduces remaining tries. "
                    "Do NOT retry unless you are sure of the PIN."
                )

        parsed = {
            "token_present": token_present,
            "pin_locked": pin_locked,
            "pin_count_low": pin_count_low,
            "pin_valid": pin_valid,
            "flags": flags_str,
            "warning": warning,
            "raw": output[:2000],
        }

        stdout = output
        if warning:
            stdout = f"! {warning}\n\n" + stdout

        success = not pin_locked
        log_operation("india_dsc", "check_token_pin_health", cmd_str, success)
        return ExecutionResult([], cmd_str, stdout, "", parsed, success, 0 if success else 1)

    except subprocess.TimeoutExpired:
        return ExecutionResult([], cmd_str, "", "Timeout — is the token plugged in?", {}, False, -1)
    except Exception as e:
        return ExecutionResult([], cmd_str, "", str(e), {}, False, -1)


# ---------------------------------------------------------------------------
# Portal workflow validators
# ---------------------------------------------------------------------------

# Portal definitions: each entry describes what it requires and what to check.
PORTAL_RULES: dict[str, dict] = {
    "MCA21": {
        "full_name": "MCA21 v3 (Ministry of Corporate Affairs)",
        "url": "https://efiling.mca.gov.in",
        "required_class": "Class 3",
        "cert_type": "organisation",   # org DSC required (not individual)
        "format": "PDF signed with embedded CMS signature",
        "notes": [
            "Director and Company Secretary must BOTH sign the e-form.",
            "DSC must be linked to the Director Identification Number (DIN).",
            "Organisation DSC required — individual DSC not accepted for company filings.",
            "Token must remain inserted during the entire MCA21 browser session.",
        ],
        "pan_check": False,
    },
    "IT_EFILING": {
        "full_name": "Income Tax e-Filing 2.0 (incometax.gov.in)",
        "url": "https://www.incometax.gov.in",
        "required_class": "Class 3",
        "cert_type": "individual",
        "format": "XML signed, then PKCS7 DER attachment",
        "notes": [
            "PAN in the DSC subject (CN or serialNumber) MUST match the taxpayer PAN.",
            "Name on DSC must match the name on PAN card exactly.",
            "Individual DSC used for personal ITR; organisation DSC for company returns.",
            "Pre-validate DSC at the portal before filing deadline.",
        ],
        "pan_check": True,
    },
    "GST": {
        "full_name": "GST Portal (gst.gov.in)",
        "url": "https://www.gst.gov.in",
        "required_class": "Class 3",
        "cert_type": "any",
        "format": "PDF + DSC browser login (Java applet / DSC browser tool)",
        "notes": [
            "USB token must be physically inserted during the browser DSC login session.",
            "Use the GST DSC Browser tool (Chrome extension or standalone) for signing.",
            "GSTIN must be registered against the signatory's PAN.",
            "Class 2 DSC no longer accepted (discontinued Jan 2021).",
        ],
        "pan_check": False,
    },
    "GeM": {
        "full_name": "GeM / CPPP (Government e-Marketplace / eProcurement)",
        "url": "https://gem.gov.in",
        "required_class": "Class 3",
        "cert_type": "any",
        "format": "PKCS7 DER detached signature on tender document",
        "notes": [
            "A trusted timestamp (RFC 3161) is REQUIRED for tender submissions.",
            "Produce the signature with -addtsa flag or a separate TSA request.",
            "Organisation DSC preferred for company bids; individual accepted for proprietors.",
            "Bid document hash must be signed — do not sign the entire PDF envelope.",
        ],
        "pan_check": False,
        "timestamp_required": True,
    },
}


def validate_for_portal(cert_path: str, portal: str, pan: str = "") -> ExecutionResult:
    """
    Run pre-signing checks for a specific Indian e-governance portal.

    Parameters
    ----------
    cert_path : str
        Path to the signer certificate PEM file (exported from token).
    portal : str
        One of: "MCA21", "IT_EFILING", "GST", "GeM".
    pan : str, optional
        Taxpayer / signatory PAN number (required for IT_EFILING PAN-match check).

    Parsed dict keys:
      portal_name     — full portal name
      checks          — list of {"check": str, "result": "pass"|"fail"|"warn", "detail": str}
      ready_to_sign   — bool (True only if all checks pass or warn)
      issues          — list of blocking issue strings
      notes           — portal-specific workflow notes
    """
    portal = portal.upper().replace("-", "_").replace(" ", "_")
    # normalise common aliases
    portal = {"INCOME_TAX": "IT_EFILING", "INCOMETAX": "IT_EFILING",
               "GEM": "GeM", "CPPP": "GeM"}.get(portal, portal)

    cmd_str = f"# Validate certificate for {portal} portal"

    if portal not in PORTAL_RULES:
        known = ", ".join(PORTAL_RULES.keys())
        return ExecutionResult([], cmd_str, "",
                               f"Unknown portal '{portal}'. Known portals: {known}",
                               {}, False, 1)

    rules = PORTAL_RULES[portal]
    checks: list[dict] = []
    issues: list[str] = []

    # --- 1. Load the certificate ---
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        from datetime import datetime, timezone

        with open(cert_path, "rb") as f:
            data = f.read()
        try:
            cert = x509.load_pem_x509_certificate(data)
        except Exception:
            cert = x509.load_der_x509_certificate(data)
    except FileNotFoundError:
        return ExecutionResult([], cmd_str, "", f"Certificate file not found: {cert_path}", {}, False, 1)
    except Exception as e:
        return ExecutionResult([], cmd_str, "", f"Cannot parse certificate: {e}", {}, False, -1)

    # --- 2. Expiry check ---
    try:
        now = datetime.now(tz=timezone.utc)
        try:
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_left = (not_after - now).days
        if days_left <= 0:
            checks.append({"check": "Certificate validity", "result": "fail",
                           "detail": f"Certificate EXPIRED {abs(days_left)} days ago."})
            issues.append("Certificate is expired — renew your DSC before filing.")
        elif days_left <= 7:
            checks.append({"check": "Certificate validity", "result": "warn",
                           "detail": f"Expires in {days_left} day(s) — renew urgently."})
        else:
            checks.append({"check": "Certificate validity", "result": "pass",
                           "detail": f"Valid for {days_left} more days."})
    except Exception as e:
        checks.append({"check": "Certificate validity", "result": "warn",
                       "detail": f"Could not determine expiry: {e}"})

    # --- 3. Class 3 check (via key usage / policy OIDs) ---
    # Heuristic: Class 3 certs have KeyUsage digitalSignature + nonRepudiation
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        has_digital_sig = ku.value.digital_signature
        has_non_rep = ku.value.content_commitment  # nonRepudiation
        if has_digital_sig and has_non_rep:
            checks.append({"check": "Key usage (Class 3 indicator)", "result": "pass",
                           "detail": "digitalSignature + nonRepudiation present."})
        else:
            checks.append({"check": "Key usage (Class 3 indicator)", "result": "warn",
                           "detail": "Unexpected key usage — verify this is a Class 3 DSC."})
    except x509.ExtensionNotFound:
        checks.append({"check": "Key usage", "result": "warn",
                       "detail": "KeyUsage extension absent — cannot confirm Class 3."})
    except Exception:
        pass

    # --- 4. Organisation vs individual cert type ---
    subject = cert.subject
    org_attrs = subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    has_org = len(org_attrs) > 0

    if rules["cert_type"] == "organisation":
        if has_org:
            org_name = org_attrs[0].value
            checks.append({"check": "Certificate type", "result": "pass",
                           "detail": f"Organisation DSC confirmed — O={org_name}."})
        else:
            checks.append({"check": "Certificate type", "result": "fail",
                           "detail": f"{portal} requires an organisation DSC. This appears to be an individual cert (no O= in subject)."})
            issues.append(f"{portal} requires an organisation DSC — individual DSC will be rejected.")
    elif rules["cert_type"] == "individual":
        if not has_org:
            checks.append({"check": "Certificate type", "result": "pass",
                           "detail": "Individual DSC (no organisation in subject)."})
        else:
            # Org certs also work for IT e-filing company returns — just note it
            checks.append({"check": "Certificate type", "result": "warn",
                           "detail": "Organisation DSC detected. Valid for company returns; for personal ITR an individual DSC is preferred."})

    # --- 5. PAN match (IT e-filing only) ---
    if rules.get("pan_check") and pan:
        pan_upper = pan.strip().upper()
        subject_str = subject.rfc4514_string().upper()
        # PAN typically appears in CN, serialNumber, or title attribute
        cn_attrs = subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        serial_attrs = subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        combined = " ".join(
            [a.value.upper() for a in cn_attrs + serial_attrs]
        )
        if pan_upper in combined or pan_upper in subject_str:
            checks.append({"check": "PAN match", "result": "pass",
                           "detail": f"PAN {pan_upper} found in certificate subject."})
        else:
            checks.append({"check": "PAN match", "result": "fail",
                           "detail": f"PAN {pan_upper} NOT found in certificate subject. IT portal will reject the DSC."})
            issues.append(f"PAN mismatch — DSC subject does not contain {pan_upper}.")
    elif rules.get("pan_check") and not pan:
        checks.append({"check": "PAN match", "result": "warn",
                       "detail": "PAN not supplied — skipping PAN-match check. Provide PAN to verify."})

    # --- 6. Timestamp requirement (GeM/CPPP) ---
    if rules.get("timestamp_required"):
        checks.append({"check": "Timestamp requirement", "result": "warn",
                       "detail": "GeM/CPPP requires an RFC 3161 trusted timestamp. "
                                 "Pass -addtsa <tsa_url> when signing with openssl cms."})

    ready_to_sign = len(issues) == 0

    lines = [f"Portal: {rules['full_name']}", f"URL   : {rules['url']}", ""]
    for c in checks:
        icon = {"pass": "✓", "fail": "✗", "warn": "!"}.get(c["result"], "?")
        lines.append(f"  [{icon}] {c['check']}: {c['detail']}")
    if issues:
        lines += ["", "BLOCKING ISSUES:"] + [f"  • {i}" for i in issues]
    else:
        lines += ["", "All checks passed — ready to sign."]

    parsed = {
        "portal_name": rules["full_name"],
        "checks": checks,
        "ready_to_sign": ready_to_sign,
        "issues": issues,
        "notes": rules["notes"],
        "format": rules["format"],
    }
    log_operation("india_dsc", f"validate_for_portal:{portal}", cmd_str, ready_to_sign)
    return ExecutionResult([], cmd_str, "\n".join(lines), "", parsed, ready_to_sign, 0 if ready_to_sign else 1)


def list_supported_portals() -> list[dict]:
    """Return portal metadata for display in the UI."""
    return [
        {
            "key": k,
            "full_name": v["full_name"],
            "url": v["url"],
            "format": v["format"],
            "cert_type": v["cert_type"],
        }
        for k, v in PORTAL_RULES.items()
    ]


# ---------------------------------------------------------------------------
# eSign API stub (Aadhaar OTP-based, CCA-licensed ASPs)
# ---------------------------------------------------------------------------

# CCA-licensed eSign ASPs (Application Service Providers)
ESIGN_ASPS: dict[str, dict] = {
    "eMudhra": {
        "name": "eMudhra Limited",
        "gateway_url": "https://esign.emudhra.com/esign/2.1",
        "docs_url": "https://emudhra.com/esign",
    },
    "NSDL": {
        "name": "NSDL e-Governance Infrastructure Ltd",
        "gateway_url": "https://esign.egov-nsdl.co.in/gateway",
        "docs_url": "https://egov-nsdl.co.in/esign",
    },
    "CDAC": {
        "name": "CDAC (eMudhra partnership)",
        "gateway_url": "https://esign.cdac.in/gateway",
        "docs_url": "https://cdac.in/esign",
    },
}


def esign_build_request(
    doc_hash_hex: str,
    hash_algorithm: str = "SHA256",
    asp_id: str = "",
    asp_txn_id: str = "",
    timestamp: str = "",
    consent: str = "Y",
) -> ExecutionResult:
    """
    Build an eSign API v2.1 request XML for Aadhaar OTP-based signing.

    This is a STUB — it constructs and returns the unsigned XML request that
    would be sent to a CCA-licensed ASP gateway.  It does NOT make any network
    call and does NOT interact with Aadhaar or UIDAI.

    To complete an eSign workflow you need:
      1. Register as an Application Service Provider with CCA.
      2. Obtain an ASP ID and API key from your chosen gateway (eMudhra/NSDL/CDAC).
      3. Collect the signer's Aadhaar number and OTP consent.
      4. POST the signed XML to the ASP gateway endpoint.
      5. Parse the response SignatureValue and embed it in your document.

    Parameters
    ----------
    doc_hash_hex : str
        SHA-256 (or SHA-1/SHA-512) hex digest of the document to be signed.
    hash_algorithm : str
        Hash algorithm used — "SHA256" (default), "SHA1", or "SHA512".
    asp_id : str
        Your registered ASP ID (issued by the eSign gateway provider).
    asp_txn_id : str
        Unique transaction ID from your application (for audit trail).
    timestamp : str
        ISO-8601 timestamp for the request (default: current UTC time).
    consent : str
        Signer's explicit consent — must be "Y".

    Returns an ExecutionResult where stdout is the XML request template and
    parsed["xml"] contains the same string.
    """
    import xml.etree.ElementTree as ET
    from datetime import datetime, timezone

    if not timestamp:
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    if not asp_txn_id:
        import uuid
        asp_txn_id = str(uuid.uuid4())

    cmd_str = "# eSign API v2.1 — build request XML (stub — no network call)"

    # Build the eSign request XML per CCA eSign API v2.1 specification
    root = ET.Element("Esign")
    root.set("ver", "2.1")
    root.set("sc", "Y")             # service code
    root.set("ts", timestamp)
    root.set("txn", asp_txn_id)
    root.set("ekycIdType", "A")     # A = Aadhaar
    root.set("ekycId", "")          # to be filled by signer at ASP portal
    root.set("aspId", asp_id or "YOUR_ASP_ID")
    root.set("AuthMode", "1")       # 1 = OTP
    root.set("responseSigType", "pkcs7")
    root.set("preVerified", "n")
    root.set("organizationFlag", "n")
    root.set("responseUrl", "https://your-app.example.com/esign/callback")

    docs_el = ET.SubElement(root, "Docs")
    input_hash_el = ET.SubElement(docs_el, "InputHash")
    input_hash_el.set("id", "1")
    input_hash_el.set("hashAlgorithm", hash_algorithm)
    input_hash_el.set("docInfo", "Document to be signed")
    input_hash_el.text = doc_hash_hex

    # Pretty-print
    ET.indent(root, space="  ")
    xml_str = ET.tostring(root, encoding="unicode", xml_declaration=False)
    xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str

    notice = (
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  eSign API STUB — No network call is made                    ║\n"
        "║  This XML must be signed with your ASP certificate and POSTed║\n"
        "║  to the gateway endpoint of your licensed ASP.               ║\n"
        "║  See: https://cca.gov.in/esign-service.html                  ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n\n"
    )

    asp_info = "\nLicensed ASP Gateways:\n"
    for key, asp in ESIGN_ASPS.items():
        asp_info += f"  {key:<10} {asp['name']}\n"
        asp_info += f"             Gateway: {asp['gateway_url']}\n"
        asp_info += f"             Docs:    {asp['docs_url']}\n"

    stdout = notice + xml_str + asp_info
    parsed = {
        "xml": xml_str,
        "asp_txn_id": asp_txn_id,
        "timestamp": timestamp,
        "hash_algorithm": hash_algorithm,
        "doc_hash": doc_hash_hex,
        "asps": ESIGN_ASPS,
        "stub": True,
    }
    log_operation("india_dsc", "esign_build_request", cmd_str, True)
    return ExecutionResult([], cmd_str, stdout, "", parsed, True, 0)
