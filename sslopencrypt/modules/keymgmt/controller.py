"""
modules/keymgmt/controller.py — Module 1: Key Management

Supported operations:
  - generate_key: RSA, ECDSA, Ed25519, Ed448, X25519, X448
  - inspect_key: show modulus, exponent, curve, key length, fingerprint
  - convert_key: PEM ↔ DER ↔ PKCS#8 ↔ PKCS#1
  - extract_public: derive public key from private
"""

import os
import re
from pathlib import Path

from core.audit_log import log_operation
from core.executor import run_openssl
from core.result import ExecutionResult
from core.tempfile_manager import secure_temp_file


# Algorithms available in Beginner Mode (safe defaults only)
BEGINNER_ALGORITHMS = ["RSA-2048", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "Ed25519"]

# All supported algorithms (Expert Mode)
ALL_ALGORITHMS = [
    "RSA-1024", "RSA-2048", "RSA-3072", "RSA-4096", "RSA-8192",
    "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
    "ECDSA-secp256k1",
    "Ed25519", "Ed448", "X25519", "X448",
    "DSA-2048", "DSA-3072",
]

_CURVE_MAP = {
    "P256": "prime256v1",
    "P384": "secp384r1",
    "P521": "secp521r1",
    "secp256k1": "secp256k1",
}


def generate_key(
    algorithm: str,
    passphrase: str | None,
    output_path: str,
) -> ExecutionResult:
    """
    Generate an asymmetric key pair.

    algorithm: one of ALL_ALGORITHMS (e.g. "RSA-4096", "ECDSA-P256", "Ed25519")
    passphrase: if set, the private key is AES-256-CBC protected
    output_path: path for the private key PEM file (public key written to <path>.pub)
    """
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    alg_upper = algorithm.upper()
    results = []

    priv_out = output_path
    pub_out = str(output_path).replace(".pem", "") + "_pub.pem"
    if not pub_out.endswith(".pem"):
        pub_out += "_pub.pem"

    if alg_upper.startswith("RSA"):
        bits = int(alg_upper.split("-")[1])
        cmd = ["genpkey", "-algorithm", "RSA", f"-pkeyopt", f"rsa_keygen_bits:{bits}"]
        if passphrase:
            cmd += ["-aes-256-cbc", "-pass", f"pass:{passphrase}"]
        cmd += ["-out", priv_out]
        r1 = run_openssl(cmd)
        results.append(r1)
        if r1.success:
            pub_cmd = ["pkey", "-in", priv_out]
            if passphrase:
                pub_cmd += ["-passin", f"pass:{passphrase}"]
            pub_cmd += ["-pubout", "-out", pub_out]
            r2 = run_openssl(pub_cmd)
            results.append(r2)
            if r2.success:
                r2.parsed["private_key_path"] = priv_out
                r2.parsed["public_key_path"] = pub_out
                r2.parsed["algorithm"] = f"RSA-{bits}"

    elif alg_upper.startswith("ECDSA") or alg_upper.startswith("EC-"):
        curve_part = alg_upper.replace("ECDSA-", "").replace("EC-", "")
        curve = _CURVE_MAP.get(curve_part, curve_part.lower())
        with secure_temp_file(suffix=".pem", prefix="ecparam_") as param_file:
            r_param = run_openssl(["ecparam", "-name", curve, "-genkey", "-noout", "-out", param_file.path])
            if not r_param.success:
                return r_param
            # Convert to PKCS#8
            cmd2 = ["pkcs8", "-topk8", "-in", param_file.path]
            if passphrase:
                cmd2 += ["-out", priv_out, "-v2", "aes-256-cbc", "-passout", f"pass:{passphrase}"]
            else:
                cmd2 += ["-out", priv_out, "-nocrypt"]
            r1 = run_openssl(cmd2)
            results.append(r1)
            if r1.success:
                pub_cmd = ["pkey", "-in", priv_out]
                if passphrase:
                    pub_cmd += ["-passin", f"pass:{passphrase}"]
                pub_cmd += ["-pubout", "-out", pub_out]
                r2 = run_openssl(pub_cmd)
                results.append(r2)
                if r2.success:
                    r2.parsed["private_key_path"] = priv_out
                    r2.parsed["public_key_path"] = pub_out
                    r2.parsed["algorithm"] = f"ECDSA ({curve})"

    elif alg_upper in ("ED25519", "ED448", "X25519", "X448"):
        alg_name = alg_upper.replace("ED2", "ed2").replace("ED4", "ed4").replace("X2", "X2").replace("X4", "X4")
        # genpkey uses lowercase for EdDSA
        alg_openssl = {"ED25519": "ed25519", "ED448": "ed448", "X25519": "X25519", "X448": "X448"}[alg_upper]
        cmd = ["genpkey", "-algorithm", alg_openssl]
        if passphrase:
            cmd += ["-aes-256-cbc", "-pass", f"pass:{passphrase}"]
        cmd += ["-out", priv_out]
        r1 = run_openssl(cmd)
        results.append(r1)
        if r1.success:
            pub_cmd = ["pkey", "-in", priv_out]
            if passphrase:
                pub_cmd += ["-passin", f"pass:{passphrase}"]
            pub_cmd += ["-pubout", "-out", pub_out]
            r2 = run_openssl(pub_cmd)
            results.append(r2)
            if r2.success:
                r2.parsed["private_key_path"] = priv_out
                r2.parsed["public_key_path"] = pub_out
                r2.parsed["algorithm"] = alg_upper

    elif alg_upper.startswith("DSA"):
        bits = int(alg_upper.split("-")[1])
        with secure_temp_file(suffix=".pem", prefix="dsaparam_") as param_file:
            # OpenSSL 3.x: numbits must be the final positional argument
            r_param = run_openssl(["dsaparam", "-genkey", "-out", param_file.path, str(bits)])
            if not r_param.success:
                return r_param
            cmd2 = ["pkcs8", "-topk8", "-in", param_file.path]
            if passphrase:
                cmd2 += ["-out", priv_out, "-v2", "aes-256-cbc", "-passout", f"pass:{passphrase}"]
            else:
                cmd2 += ["-out", priv_out, "-nocrypt"]
            r1 = run_openssl(cmd2)
            results.append(r1)
            if r1.success:
                pub_cmd = ["pkey", "-in", priv_out]
                if passphrase:
                    pub_cmd += ["-passin", f"pass:{passphrase}"]
                pub_cmd += ["-pubout", "-out", pub_out]
                r2 = run_openssl(pub_cmd)
                results.append(r2)
                if r2.success:
                    r2.parsed["private_key_path"] = priv_out
                    r2.parsed["public_key_path"] = pub_out
                    r2.parsed["algorithm"] = f"DSA-{bits}"
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    final = results[-1] if results else ExecutionResult([], "", "", "No operation performed", {}, False, -1)

    # Merge command strings for the console
    all_commands = "\n".join(r.command_str for r in results)
    final.command_str = all_commands

    log_operation(
        module="keymgmt",
        operation=f"generate_key:{algorithm}",
        command_str=all_commands,
        success=final.success,
        is_deprecated=final.is_deprecated_alg,
        deprecated_alg=final.deprecated_alg_name,
    )
    return final


def inspect_key(key_path: str, passphrase: str | None = None) -> ExecutionResult:
    """Inspect an existing key file and return structured details."""
    cmd = ["pkey", "-in", key_path, "-text", "-noout"]
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    r = run_openssl(cmd)

    if r.success:
        # Parse key details
        parsed = _parse_key_text(r.stdout)
        r.parsed.update(parsed)

        # Get fingerprint (SHA-256 of public key DER)
        fp_result = _get_key_fingerprint(key_path, passphrase)
        if fp_result.success:
            r.parsed["fingerprint_sha256"] = fp_result.stdout.strip()

    log_operation("keymgmt", "inspect_key", r.command_str, r.success)
    return r


def _get_key_fingerprint(key_path: str, passphrase: str | None) -> ExecutionResult:
    """Get the SHA-256 fingerprint of the public key."""
    with secure_temp_file(suffix="_pub.pem", prefix="fp_") as pub_file:
        cmd = ["pkey", "-in", key_path, "-pubout", "-out", pub_file.path]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
        r = run_openssl(cmd)
        if not r.success:
            return r
        return run_openssl(["pkey", "-in", pub_file.path, "-pubin", "-text", "-noout"])


def _parse_key_text(text: str) -> dict:
    """Extract key type, size, and other fields from pkey -text output."""
    parsed = {}
    if ("RSA Private Key" in text or "Private-Key: (RSA" in text
            or "RSA key" in text.lower() or "publicExponent:" in text):
        parsed["key_type"] = "RSA"
        m = re.search(r"Private-Key:\s*\((\d+)\s*bit", text)
        if m:
            parsed["key_bits"] = int(m.group(1))
    elif "EC Private Key" in text or "id-ecPublicKey" in text or "NIST CURVE" in text:
        parsed["key_type"] = "ECDSA"
        m = re.search(r"NIST CURVE:\s*(\S+)", text)
        if m:
            parsed["curve"] = m.group(1)
    elif "ED25519" in text.upper():
        parsed["key_type"] = "Ed25519"
    elif "ED448" in text.upper():
        parsed["key_type"] = "Ed448"
    elif "X25519" in text.upper():
        parsed["key_type"] = "X25519"
    elif "X448" in text.upper():
        parsed["key_type"] = "X448"
    elif "DSA Private Key" in text:
        parsed["key_type"] = "DSA"
    # Ensure algorithm mirrors key_type for all types that don't set it explicitly
    if "key_type" in parsed and "algorithm" not in parsed:
        parsed["algorithm"] = parsed["key_type"]
    return parsed


def extract_public_key(private_key_path: str, output_path: str, passphrase: str | None = None) -> ExecutionResult:
    """Extract the public key from a private key file."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = ["pkey", "-in", private_key_path, "-pubout", "-out", output_path]
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    r = run_openssl(cmd)
    log_operation("keymgmt", "extract_public_key", r.command_str, r.success)
    return r


def convert_key(
    input_path: str,
    output_path: str,
    input_format: str,   # "PEM" | "DER"
    output_format: str,  # "PEM" | "DER" | "PKCS8" | "PKCS1"
    passphrase: str | None = None,
) -> ExecutionResult:
    """Convert a key between formats."""
    output_path = os.path.expanduser(output_path)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    cmd = ["pkey", "-in", input_path]
    if input_format.upper() == "DER":
        cmd += ["-inform", "DER"]
    if passphrase:
        cmd += ["-passin", f"pass:{passphrase}"]
    if output_format.upper() == "DER":
        cmd += ["-out", output_path, "-outform", "DER"]
    elif output_format.upper() == "PKCS8":
        cmd += ["-out", output_path]
    elif output_format.upper() == "PKCS1":
        # For RSA only — traditional format
        cmd = ["rsa", "-in", input_path, "-out", output_path]
        if passphrase:
            cmd += ["-passin", f"pass:{passphrase}"]
    else:
        cmd += ["-out", output_path]
    r = run_openssl(cmd)
    log_operation("keymgmt", f"convert_key:{input_format}->{output_format}", r.command_str, r.success)
    return r
