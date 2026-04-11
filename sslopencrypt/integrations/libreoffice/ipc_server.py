"""
integrations/libreoffice/ipc_server.py
sslOpenCrypt LibreOffice IPC Server.

A lightweight JSON-over-TCP socket server (localhost:47251) that the
LibreOffice Basic macro calls to request cryptographic operations without
launching a new process for every operation.

Protocol (newline-delimited JSON):
  Request:  {"op": "sign"|"verify"|"hash"|"encrypt"|"decrypt",
             "file": "/path/to/doc",
             "output": "/path/to/output",    # optional
             "passphrase": "...",            # optional — never logged
             "algorithm": "SHA-256",         # optional
             "cipher": "AES-256-GCM"}        # optional

  Response: {"success": true|false,
             "command": "openssl ...",
             "result": "...",
             "error": "..."}

Start the server:
  python3 ipc_server.py [--port 47251] [--host 127.0.0.1]

The server binds only to 127.0.0.1 (loopback) — it is NOT accessible
from the network. Each connection handles one request and closes.

Usage from LibreOffice Basic macro:
  See sslopencrypt_macro.bas for the complete macro that calls this server.

Security notes:
  - Binds to 127.0.0.1 only (loopback — no network exposure)
  - No authentication required (localhost-only — single-user workstation)
  - Passphrases are never written to disk or logged
  - All temp files use tempfile.mkstemp() with mode 0o600
"""

import argparse
import json
import os
import socket
import sys
import threading
from pathlib import Path

# Add project root to sys.path so we can import sslOpenCrypt modules
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 47251
_BANNER = f"sslOpenCrypt LibreOffice IPC Server — listening on {DEFAULT_HOST}:{DEFAULT_PORT}"


# ---------------------------------------------------------------------------
# Request handlers
# ---------------------------------------------------------------------------

def _handle_sign(req: dict) -> dict:
    file_path = req.get("file", "")
    output = req.get("output", file_path + ".p7s")
    passphrase = req.get("passphrase", "")

    from modules.signing.controller import sign_file
    r = sign_file(file_path, output, passphrase=passphrase or None)
    return {"success": r.success, "command": r.command_str,
            "result": r.stdout or r.stderr, "output": output,
            "error": r.stderr if not r.success else ""}


def _handle_verify(req: dict) -> dict:
    file_path = req.get("file", "")
    sig_path = req.get("signature", file_path + ".p7s")

    from modules.signing.controller import verify_file
    r = verify_file(file_path, sig_path)
    return {"success": r.success, "command": r.command_str,
            "result": r.stdout, "error": r.stderr if not r.success else ""}


def _handle_hash(req: dict) -> dict:
    file_path = req.get("file", "")
    algorithm = req.get("algorithm", "SHA-256")

    from modules.hashing.controller import hash_file
    r = hash_file(file_path, algorithm)
    digest = r.parsed.get("digest", r.stdout)
    return {"success": r.success, "command": r.command_str,
            "result": digest, "error": r.stderr if not r.success else ""}


def _handle_encrypt(req: dict) -> dict:
    file_path = req.get("file", "")
    output = req.get("output", file_path + ".enc")
    cipher = req.get("cipher", "AES-256-GCM")
    passphrase = req.get("passphrase", "")

    if not passphrase:
        return {"success": False, "error": "passphrase required for encrypt"}

    from modules.symmetric.controller import encrypt_file
    r = encrypt_file(file_path, output, cipher, passphrase)
    return {"success": r.success, "command": r.command_str,
            "result": r.stdout, "output": output,
            "error": r.stderr if not r.success else ""}


def _handle_decrypt(req: dict) -> dict:
    file_path = req.get("file", "")
    output = req.get("output", "")
    cipher = req.get("cipher", "AES-256-GCM")
    passphrase = req.get("passphrase", "")

    if not output:
        # Strip last extension for output
        p = Path(file_path)
        output = str(p.parent / p.stem)
    if not passphrase:
        return {"success": False, "error": "passphrase required for decrypt"}

    from modules.symmetric.controller import decrypt_file
    r = decrypt_file(file_path, output, cipher, passphrase)
    return {"success": r.success, "command": r.command_str,
            "result": r.stdout, "output": output,
            "error": r.stderr if not r.success else ""}


_HANDLERS = {
    "sign":    _handle_sign,
    "verify":  _handle_verify,
    "hash":    _handle_hash,
    "encrypt": _handle_encrypt,
    "decrypt": _handle_decrypt,
}


# ---------------------------------------------------------------------------
# Connection handler
# ---------------------------------------------------------------------------

def _handle_connection(conn: socket.socket, addr):
    try:
        data = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break

        line = data.split(b"\n")[0].strip()
        if not line:
            return

        req = json.loads(line.decode("utf-8"))
        op = req.get("op", "").lower()

        if op not in _HANDLERS:
            resp = {"success": False, "error": f"Unknown operation: {op}"}
        else:
            try:
                resp = _HANDLERS[op](req)
            except Exception as e:
                resp = {"success": False, "error": str(e)}

        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))

    except json.JSONDecodeError as e:
        resp = {"success": False, "error": f"Invalid JSON: {e}"}
        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
    except Exception as e:
        try:
            resp = {"success": False, "error": str(e)}
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
        except Exception:
            pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class IPCServer:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._running = False

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._running = True
        print(f"{_BANNER}\nPort: {self.port}  (loopback only — not network-accessible)")
        while self._running:
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(target=_handle_connection, args=(conn, addr), daemon=True)
                t.start()
            except OSError:
                break

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass


def is_running(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> bool:
    """Check if the IPC server is already running on the given port."""
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except (ConnectionRefusedError, OSError):
        return False


def send_request(request: dict, host: str = DEFAULT_HOST,
                 port: int = DEFAULT_PORT) -> dict:
    """Send a single request to a running IPC server and return the response."""
    with socket.create_connection((host, port), timeout=30) as s:
        s.sendall((json.dumps(request) + "\n").encode("utf-8"))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\n" in data:
                break
    return json.loads(data.split(b"\n")[0].decode("utf-8"))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="sslOpenCrypt LibreOffice IPC Server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    server = IPCServer(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.stop()
