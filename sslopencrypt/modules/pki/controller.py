"""
modules/pki/controller.py — Module 4: PKI & Certificate Management

Operations:
  - create_csr: generate a Certificate Signing Request
  - create_self_signed: generate a self-signed X.509 certificate
  - inspect_cert: parse and display certificate details
  - create_root_ca: initialise a root CA
  - sign_csr: CA signs a CSR to issue a certificate
  - create_pkcs12: bundle cert + key into a PKCS#12 file
  - inspect_tls: retrieve and display a remote server's certificate chain
  - check_ocsp: query an OCSP responder
"""

import os
import re
import textwrap
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult
from core.tempfile_manager import secure_temp_file


# ---------------------------------------------------------------------------
# CSR Builder
# ---------------------------------------------------------------------------

def create_csr(
    key_path: str,
    output_path: str,
    subject: dict,
    san_list: list[str] | None = None,
    passphrase: str | None = None,
    digest: str = "sha256",
) -> ExecutionResult:
    """
    Generate a Certificate Signing Request (CSR).

    subject: dict with keys: CN, O, OU, C, ST, L, emailAddress
    san_list: list of SAN entries, e.g. ["DNS:example.com", "IP:10.0.0.1", "email:admin@example.com"]
    """
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    subj_str = _build_subject(subject)

    with secure_temp_file(suffix=".cnf", prefix="csr_") as cnf:
        cnf_content = _build_openssl_cnf(san_list)
        cnf.write(cnf_content)

        cmd = [
            "req", "-new",
            f"-{digest}",
            "-key", key_path,
            "-out", output_path,
            "-subj", subj_str,
        ]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
        if san_list:
            cmd += ["-config", cnf.path]

        r = run_openssl(cmd)

    log_operation("pki", "create_csr", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Self-Signed Certificate
# ---------------------------------------------------------------------------

def create_self_signed(
    key_path: str,
    output_path: str,
    subject: dict,
    days: int = 365,
    san_list: list[str] | None = None,
    passphrase: str | None = None,
    digest: str = "sha256",
    is_ca: bool = False,
) -> ExecutionResult:
    """Generate a self-signed certificate."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    subj_str = _build_subject(subject)

    with secure_temp_file(suffix=".cnf", prefix="selfsign_") as cnf:
        cnf_content = _build_openssl_cnf(san_list, is_ca=is_ca)
        cnf.write(cnf_content)

        cmd = [
            "req", "-x509", "-new",
            f"-{digest}",
            "-key", key_path,
            "-out", output_path,
            "-days", str(days),
            "-subj", subj_str,
        ]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
        if san_list or is_ca:
            cmd += ["-config", cnf.path, "-extensions", "v3_ca" if is_ca else "v3_req"]

        r = run_openssl(cmd)

    log_operation("pki", "create_self_signed", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Root CA & Intermediate CA
# ---------------------------------------------------------------------------

def create_root_ca(
    key_path: str,
    cert_output: str,
    subject: dict,
    days: int = 3650,
    passphrase: str | None = None,
    digest: str = "sha256",
) -> ExecutionResult:
    """Create a root CA certificate (self-signed, CA:TRUE extension)."""
    return create_self_signed(
        key_path=key_path,
        output_path=cert_output,
        subject=subject,
        days=days,
        passphrase=passphrase,
        digest=digest,
        is_ca=True,
    )


def sign_csr(
    ca_cert_path: str,
    ca_key_path: str,
    csr_path: str,
    output_path: str,
    days: int = 365,
    passphrase: str | None = None,
    digest: str = "sha256",
    serial: int | None = None,
    san_list: list[str] | None = None,
) -> ExecutionResult:
    """CA signs a CSR to issue an end-entity certificate."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with secure_temp_file(suffix=".cnf", prefix="sign_") as cnf:
        cnf_content = _build_openssl_cnf(san_list, is_ca=False)
        cnf.write(cnf_content)

        cmd = [
            "x509", "-req",
            f"-{digest}",
            "-in", csr_path,
            "-CA", ca_cert_path,
            "-CAkey", ca_key_path,
            "-out", output_path,
            "-days", str(days),
            "-CAcreateserial",
        ]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
        if san_list:
            cmd += ["-extfile", cnf.path, "-extensions", "v3_req"]

        r = run_openssl(cmd)

    log_operation("pki", "sign_csr", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Certificate Inspection
# ---------------------------------------------------------------------------

def inspect_cert(cert_path: str, format: str = "PEM") -> ExecutionResult:
    """Inspect a certificate and return structured fields."""
    cmd = ["x509", "-in", cert_path, "-text", "-noout"]
    if format.upper() == "DER":
        cmd += ["-inform", "DER"]
    r = run_openssl(cmd)

    if r.success:
        r.parsed.update(_parse_cert_text(r.stdout))

    log_operation("pki", "inspect_cert", r.command_str, r.success)
    return r


def inspect_cert_chain(bundle_path: str) -> ExecutionResult:
    """Inspect all certs in a PEM bundle file."""
    cmd = ["crl2pkcs7", "-nocrl", "-certfile", bundle_path]
    r = run_openssl(cmd)
    if r.success:
        cmd2 = ["pkcs7", "-print_certs", "-text", "-noout"]
        r2 = run_openssl(cmd2, input_data=r.stdout.encode())
        return r2
    return r


def verify_cert_chain(cert_path: str, ca_bundle: str | None = None) -> ExecutionResult:
    """Verify a certificate against a CA bundle."""
    cmd = ["verify"]
    if ca_bundle:
        cmd += ["-CAfile", ca_bundle]
    cmd += [cert_path]
    r = run_openssl(cmd)
    r.parsed["verified"] = r.success
    log_operation("pki", "verify_cert", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# PKCS#12 / PFX
# ---------------------------------------------------------------------------

def create_pkcs12(
    cert_path: str,
    key_path: str,
    output_path: str,
    password: str,
    ca_bundle: str | None = None,
    friendly_name: str = "sslOpenCrypt",
    key_passphrase: str | None = None,
) -> ExecutionResult:
    """Create a PKCS#12 bundle."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "pkcs12", "-export",
        "-inkey", key_path,
        "-in", cert_path,
        "-out", output_path,
        "-passout", f"pass:{password}",
        "-name", friendly_name,
    ]
    if key_passphrase:
        cmd += ["-passin", f"pass:{key_passphrase}"]
    if ca_bundle:
        cmd += ["-certfile", ca_bundle, "-chain"]
    r = run_openssl(cmd)
    log_operation("pki", "create_pkcs12", r.command_str, r.success)
    return r


def import_pkcs12(
    pfx_path: str,
    password: str,
    cert_output: str,
    key_output: str,
    ca_output: str | None = None,
) -> ExecutionResult:
    """Extract certificate and key from a PKCS#12 file."""
    cert_output = os.path.expanduser(cert_output)
    key_output = os.path.expanduser(key_output)
    Path(cert_output).parent.mkdir(parents=True, exist_ok=True)
    Path(key_output).parent.mkdir(parents=True, exist_ok=True)
    if ca_output:
        ca_output = os.path.expanduser(ca_output)
        Path(ca_output).parent.mkdir(parents=True, exist_ok=True)
    # Extract certificate
    r1 = run_openssl([
        "pkcs12", "-in", pfx_path,
        "-clcerts", "-nokeys",
        "-out", cert_output,
        "-passin", f"pass:{password}",
        "-passout", "pass:",
    ])
    # Extract key
    r2 = run_openssl([
        "pkcs12", "-in", pfx_path,
        "-nocerts", "-nodes",
        "-out", key_output,
        "-passin", f"pass:{password}",
    ])
    if ca_output:
        run_openssl([
            "pkcs12", "-in", pfx_path,
            "-cacerts", "-nokeys",
            "-out", ca_output,
            "-passin", f"pass:{password}",
        ])
    combined_cmd = f"{r1.command_str}\n{r2.command_str}"
    success = r1.success and r2.success
    log_operation("pki", "import_pkcs12", combined_cmd, success)
    r2.command_str = combined_cmd
    return r2


# ---------------------------------------------------------------------------
# TLS Inspector (openssl s_client)
# ---------------------------------------------------------------------------

def inspect_tls(host: str, port: int = 443) -> ExecutionResult:
    """
    Retrieve and display the TLS certificate chain from a remote server.
    Equivalent to: echo | openssl s_client -connect host:port -showcerts
    """
    cmd = [
        "s_client",
        "-connect", f"{host}:{port}",
        "-showcerts",
        "-servername", host,
        "-status",
    ]
    r = run_openssl(cmd, input_data=b"", timeout=30)
    if r.success or r.stdout:
        r.parsed["host"] = host
        r.parsed["port"] = port
        # Extract cert subjects from s_client output
        subjects = re.findall(r"subject=(.+)", r.stdout)
        r.parsed["subjects"] = [s.strip() for s in subjects]
    log_operation("pki", f"inspect_tls:{host}:{port}", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# OCSP
# ---------------------------------------------------------------------------

def check_ocsp(
    cert_path: str,
    issuer_path: str,
    ocsp_url: str,
) -> ExecutionResult:
    """Query an OCSP responder for certificate revocation status."""
    cmd = [
        "ocsp",
        "-issuer", issuer_path,
        "-cert", cert_path,
        "-url", ocsp_url,
        "-text",
    ]
    r = run_openssl(cmd, timeout=30)
    log_operation("pki", "check_ocsp", r.command_str, r.success)
    return r


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_subject(subject: dict) -> str:
    parts = []
    for key in ["C", "ST", "L", "O", "OU", "CN", "emailAddress"]:
        val = subject.get(key, "").strip()
        if val:
            # Escape forward slashes in values
            parts.append(f"/{key}={val.replace('/', '/')}")
    return "".join(parts) if parts else "/CN=sslOpenCrypt"


def _build_openssl_cnf(san_list: list[str] | None, is_ca: bool = False) -> str:
    lines = [
        "[req]",
        "distinguished_name = req_distinguished_name",
        "req_extensions = v3_req",
        "prompt = no",
        "",
        "[req_distinguished_name]",
        "",
        "[v3_req]",
        "basicConstraints = CA:FALSE",
        "keyUsage = nonRepudiation, digitalSignature, keyEncipherment",
    ]
    if san_list:
        lines.append("subjectAltName = @alt_names")
        lines.append("")
        lines.append("[alt_names]")
        dns_count = ip_count = email_count = uri_count = 1
        for entry in san_list:
            if entry.startswith("DNS:"):
                lines.append(f"DNS.{dns_count} = {entry[4:]}")
                dns_count += 1
            elif entry.startswith("IP:"):
                lines.append(f"IP.{ip_count} = {entry[3:]}")
                ip_count += 1
            elif entry.startswith("email:"):
                lines.append(f"email.{email_count} = {entry[6:]}")
                email_count += 1
            elif entry.startswith("URI:"):
                lines.append(f"URI.{uri_count} = {entry[4:]}")
                uri_count += 1

    lines += [
        "",
        "[v3_ca]",
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid:always,issuer",
        "basicConstraints = critical, CA:true",
        "keyUsage = critical, digitalSignature, cRLSign, keyCertSign",
    ]
    return "\n".join(lines) + "\n"


def _parse_cert_text(text: str) -> dict:
    """Extract key fields from x509 -text output."""
    parsed = {}
    m = re.search(r"Subject:\s*(.+)", text)
    if m:
        parsed["subject"] = m.group(1).strip()
    m = re.search(r"Issuer:\s*(.+)", text)
    if m:
        parsed["issuer"] = m.group(1).strip()
    m = re.search(r"Not Before\s*:\s*(.+)", text)
    if m:
        parsed["not_before"] = m.group(1).strip()
    m = re.search(r"Not After\s*:\s*(.+)", text)
    if m:
        parsed["not_after"] = m.group(1).strip()
    m = re.search(r"Serial Number:\s*\n?\s*(.+)", text)
    if m:
        parsed["serial"] = m.group(1).strip()
    # SANs
    sans = re.findall(r"DNS:([^\s,]+)|IP Address:([^\s,]+)|email:([^\s,]+)", text)
    if sans:
        san_list = []
        for dns, ip, email in sans:
            if dns:
                san_list.append(f"DNS:{dns}")
            if ip:
                san_list.append(f"IP:{ip}")
            if email:
                san_list.append(f"email:{email}")
        parsed["san"] = san_list
    # Key usage
    m = re.search(r"X509v3 Key Usage[^:]*:\s*\n?\s*(.+)", text)
    if m:
        parsed["key_usage"] = m.group(1).strip()
    # Signature algorithm
    m = re.search(r"Signature Algorithm:\s*(.+)", text)
    if m:
        parsed["sig_algorithm"] = m.group(1).strip()
    # Public key size
    m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
    if m:
        parsed["public_key_bits"] = int(m.group(1))
    return parsed
