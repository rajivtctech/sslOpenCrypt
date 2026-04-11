"""
cli/main.py — sslOpenCrypt headless batch/CLI mode.

Usage examples:
  sslopencrypt --mode hash --algorithm sha256 --file document.pdf
  sslopencrypt --mode keygen --algorithm Ed25519 --output private.pem
  sslopencrypt --mode encrypt --cipher AES-256-GCM --in plain.txt --out enc.bin --pass mypassword
  sslopencrypt --mode verify --file document.pdf --signature document.p7s
  sslopencrypt --mode tls --host example.com --port 443

Output: JSON to stdout; errors to stderr. Exit code 0 = success, 1 = failure.
"""

import argparse
import json
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _result_to_dict(r) -> dict:
    return {
        "command": r.command_str,
        "success": r.success,
        "exit_code": r.exit_code,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "parsed": r.parsed,
        "deprecated_alg": r.is_deprecated_alg,
    }


def cmd_hash(args) -> dict:
    from modules.hashing.controller import hash_file, hash_text, hmac_file
    if args.file:
        r = hash_file(args.file, args.algorithm or "SHA-256")
    elif args.text:
        r = hash_text(args.text, args.algorithm or "SHA-256")
    else:
        return {"success": False, "error": "Provide --file or --text"}
    return _result_to_dict(r)


def cmd_keygen(args) -> dict:
    from modules.keymgmt.controller import generate_key
    if not args.output:
        return {"success": False, "error": "--output required for keygen"}
    r = generate_key(
        algorithm=args.algorithm or "Ed25519",
        passphrase=args.passphrase or None,
        output_path=args.output,
    )
    return _result_to_dict(r)


def cmd_encrypt(args) -> dict:
    from modules.symmetric.controller import encrypt_file, encrypt_text
    if not args.passphrase:
        return {"success": False, "error": "--pass required for encryption"}
    cipher = args.cipher or "AES-256-GCM"
    if args.file:
        if not args.output:
            return {"success": False, "error": "--out required"}
        r = encrypt_file(args.file, args.output, cipher, args.passphrase)
    elif args.text:
        r = encrypt_text(args.text, cipher, args.passphrase)
    else:
        return {"success": False, "error": "Provide --file or --text"}
    return _result_to_dict(r)


def cmd_decrypt(args) -> dict:
    from modules.symmetric.controller import decrypt_file, decrypt_text
    if not args.passphrase:
        return {"success": False, "error": "--pass required"}
    cipher = args.cipher or "AES-256-GCM"
    if args.file:
        if not args.output:
            return {"success": False, "error": "--out required"}
        r = decrypt_file(args.file, args.output, cipher, args.passphrase)
    else:
        return {"success": False, "error": "Provide --file"}
    return _result_to_dict(r)


def cmd_sign(args) -> dict:
    from modules.signing.controller import sign_raw, sign_file
    if not args.key:
        return {"success": False, "error": "--key required"}
    if not args.file:
        return {"success": False, "error": "--file required"}
    if not args.output:
        return {"success": False, "error": "--out required"}
    if args.cert:
        r = sign_file(args.file, args.key, args.cert, args.output,
                      passphrase=args.passphrase or None)
    else:
        r = sign_raw(args.file, args.key, args.output,
                     passphrase=args.passphrase or None)
    return _result_to_dict(r)


def cmd_verify(args) -> dict:
    from modules.signing.controller import verify_raw, verify_file, verify_bin_signed
    if args.firmware_signed:
        if not args.key:
            return {"success": False, "error": "--key (public key) required"}
        r = verify_bin_signed(args.firmware_signed, args.key)
    elif args.signature and args.file:
        if args.key:
            r = verify_raw(args.file, args.signature, args.key)
        else:
            r = verify_file(args.file, args.signature)
    else:
        return {"success": False, "error": "Provide --file --signature (or --firmware-signed --key)"}
    return _result_to_dict(r)


def cmd_tls(args) -> dict:
    from modules.tls.controller import inspect_remote
    if not args.host:
        return {"success": False, "error": "--host required"}
    r = inspect_remote(args.host, args.port or 443)
    return _result_to_dict(r)


def cmd_random(args) -> dict:
    from modules.random.controller import random_bytes, random_password
    if args.password:
        r = random_password(length=args.length or 20)
    else:
        r = random_bytes(args.length or 32, args.format or "hex")
    return _result_to_dict(r)


def cmd_version(args) -> dict:
    from core.executor import openssl_version
    ver = openssl_version()
    return {"success": True, "version": ver}


COMMANDS = {
    "hash": cmd_hash,
    "keygen": cmd_keygen,
    "encrypt": cmd_encrypt,
    "decrypt": cmd_decrypt,
    "sign": cmd_sign,
    "verify": cmd_verify,
    "tls": cmd_tls,
    "random": cmd_random,
    "version": cmd_version,
}


def main():
    parser = argparse.ArgumentParser(
        description="sslOpenCrypt CLI — batch/headless mode. Outputs JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sslopencrypt --mode hash --algorithm SHA-256 --file document.pdf
  sslopencrypt --mode keygen --algorithm Ed25519 --output private.pem
  sslopencrypt --mode encrypt --cipher AES-256-GCM --file plain.txt --out enc.bin --pass secret
  sslopencrypt --mode sign --file firmware.bin --key private.pem --out firmware.sig
  sslopencrypt --mode verify --file firmware.bin --signature firmware.sig --key public.pem
  sslopencrypt --mode tls --host example.com --port 443
  sslopencrypt --mode random --length 32 --format hex
  sslopencrypt --mode version
"""
    )
    parser.add_argument("--mode", required=True, choices=list(COMMANDS.keys()),
                        help="Operation mode")
    parser.add_argument("--algorithm", "-a", help="Algorithm (e.g. SHA-256, Ed25519, RSA-4096)")
    parser.add_argument("--cipher", help="Cipher (e.g. AES-256-GCM, ChaCha20-Poly1305)")
    parser.add_argument("--file", "-f", help="Input file path")
    parser.add_argument("--text", "-t", help="Input text string")
    parser.add_argument("--output", "--out", "-o", help="Output file path")
    parser.add_argument("--key", "-k", help="Key file (private or public .pem)")
    parser.add_argument("--cert", help="Certificate file (.pem)")
    parser.add_argument("--signature", "--sig", help="Signature file (.sig / .p7s)")
    parser.add_argument("--pass", dest="passphrase", help="Passphrase")
    parser.add_argument("--host", help="Hostname for TLS inspection")
    parser.add_argument("--port", type=int, default=443, help="Port for TLS inspection (default: 443)")
    parser.add_argument("--length", type=int, help="Length (bytes for random, chars for password)")
    parser.add_argument("--format", help="Output format: hex | base64")
    parser.add_argument("--password", action="store_true", help="Generate a random password")
    parser.add_argument("--firmware-signed", help=".bin.signed firmware file to verify (RP2350)")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    args = parser.parse_args()
    handler = COMMANDS[args.mode]
    result = handler(args)

    indent = 2 if args.pretty else None
    print(json.dumps(result, indent=indent, ensure_ascii=False))
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
