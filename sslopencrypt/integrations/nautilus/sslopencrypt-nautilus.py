"""
integrations/nautilus/sslopencrypt-nautilus.py
Nautilus Python extension for sslOpenCrypt.

Adds right-click context menu entries in Nautilus (and Nemo) file manager:
  • Encrypt with sslOpenCrypt…
  • Decrypt with sslOpenCrypt…
  • Sign with sslOpenCrypt…
  • Verify Signature…
  • Compute Hash (SHA-256)…

Installation:
  mkdir -p ~/.local/share/nautilus-python/extensions/
  cp sslopencrypt-nautilus.py ~/.local/share/nautilus-python/extensions/
  nautilus -q && nautilus &

Requirements:
  sudo apt install python3-nautilus   # provides the nautilus module binding
  pip install nautilus-python         # alternative via pip

The extension calls sslOpenCrypt in CLI mode:
  sslopencrypt --mode <mode> --file <file> [options]

If sslOpenCrypt is not on PATH it falls back to python3 <install_dir>/main.py.
"""

import os
import shutil
import subprocess
from pathlib import Path

try:
    from gi.repository import Nautilus, GObject, Gtk
    _NAUTILUS_AVAILABLE = True
except ImportError:
    _NAUTILUS_AVAILABLE = False


def _find_sslopencrypt() -> list[str]:
    """Return the command prefix to invoke sslOpenCrypt CLI."""
    # 1. On PATH
    if shutil.which("sslopencrypt"):
        return ["sslopencrypt"]
    # 2. User install
    user = Path.home() / ".local" / "lib" / "sslopencrypt" / "main.py"
    if user.exists():
        return ["python3", str(user)]
    # 3. System install
    system = Path("/opt/sslopencrypt/main.py")
    if system.exists():
        return ["python3", str(system)]
    return ["sslopencrypt"]  # let it fail with a clear error


def _run_gui(mode: str, files: list[str]):
    """Launch sslOpenCrypt GUI pre-focused on a module, passing file paths as env."""
    cmd = _find_sslopencrypt()
    env = os.environ.copy()
    env["SSLOPENCRYPT_PRELOAD_FILE"] = files[0] if files else ""
    env["SSLOPENCRYPT_PRELOAD_MODE"] = mode
    try:
        subprocess.Popen(cmd + ["--gui", f"--module={mode}"] + files,
                         env=env, start_new_session=True)
    except Exception:
        # Fallback: open GUI without args
        subprocess.Popen(cmd, start_new_session=True)


def _run_cli_hash(file_path: str):
    """Compute SHA-256 hash and show result in a Zenity dialog."""
    cmd = _find_sslopencrypt() + [
        "--mode", "hash", "--algorithm", "SHA-256", "--file", file_path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        import json
        try:
            data = json.loads(result.stdout)
            digest = data.get("parsed", {}).get("digest", result.stdout.strip())
        except (json.JSONDecodeError, KeyError):
            digest = result.stdout.strip() or result.stderr.strip()

        _show_dialog(
            title=f"SHA-256 — {Path(file_path).name}",
            message=f"File: {file_path}\n\nSHA-256:\n{digest}",
        )
    except Exception as e:
        _show_dialog("Error", str(e))


def _show_dialog(title: str, message: str):
    """Show result using Zenity (if available) or xmessage fallback."""
    if shutil.which("zenity"):
        subprocess.Popen(
            ["zenity", "--info", f"--title={title}", f"--text={message}",
             "--width=480", "--no-wrap"],
            start_new_session=True,
        )
    elif shutil.which("xmessage"):
        subprocess.Popen(
            ["xmessage", "-center", f"{title}\n\n{message}"],
            start_new_session=True,
        )


if _NAUTILUS_AVAILABLE:

    class SSLOpenCryptMenuProvider(GObject.GObject, Nautilus.MenuProvider):
        """Provides the sslOpenCrypt right-click menu in Nautilus."""

        def _get_file_paths(self, files) -> list[str]:
            return [f.get_location().get_path() for f in files
                    if f.get_uri_scheme() == "file"]

        def get_file_items(self, *args):
            # Nautilus 3.x: get_file_items(window, files)
            # Nautilus 4.x: get_file_items(files)
            files = args[-1]
            paths = self._get_file_paths(files)
            if not paths:
                return []

            menu_items = []
            sslo = Nautilus.MenuItem(
                name="SSLOpenCrypt::TopMenu",
                label="sslOpenCrypt",
                tip="Cryptographic operations with sslOpenCrypt",
            )
            submenu = Nautilus.Menu()
            sslo.set_submenu(submenu)

            # Encrypt
            enc_item = Nautilus.MenuItem(
                name="SSLOpenCrypt::Encrypt",
                label="Encrypt…",
                tip="Encrypt selected file(s) with sslOpenCrypt",
            )
            enc_item.connect("activate", lambda i, p=paths: _run_gui("symmetric", p))
            submenu.append_item(enc_item)

            # Decrypt
            dec_item = Nautilus.MenuItem(
                name="SSLOpenCrypt::Decrypt",
                label="Decrypt…",
                tip="Decrypt selected file(s) with sslOpenCrypt",
            )
            dec_item.connect("activate", lambda i, p=paths: _run_gui("symmetric", p))
            submenu.append_item(dec_item)

            submenu.append_item(Nautilus.MenuItem(
                name="SSLOpenCrypt::Sep1", label="-"))

            # Sign
            sign_item = Nautilus.MenuItem(
                name="SSLOpenCrypt::Sign",
                label="Sign…",
                tip="Create a digital signature for selected file(s)",
            )
            sign_item.connect("activate", lambda i, p=paths: _run_gui("signing", p))
            submenu.append_item(sign_item)

            # Verify
            verify_item = Nautilus.MenuItem(
                name="SSLOpenCrypt::Verify",
                label="Verify Signature…",
                tip="Verify a digital signature",
            )
            verify_item.connect("activate", lambda i, p=paths: _run_gui("signing", p))
            submenu.append_item(verify_item)

            submenu.append_item(Nautilus.MenuItem(
                name="SSLOpenCrypt::Sep2", label="-"))

            # Hash (single file only — inline result)
            if len(paths) == 1:
                hash_item = Nautilus.MenuItem(
                    name="SSLOpenCrypt::Hash",
                    label="Compute SHA-256…",
                    tip="Compute SHA-256 hash and display result",
                )
                hash_item.connect("activate", lambda i, p=paths[0]: _run_cli_hash(p))
                submenu.append_item(hash_item)

            menu_items.append(sslo)
            return menu_items

        def get_background_items(self, *args):
            return []

else:
    # If nautilus bindings are not installed, provide a stub so the file
    # doesn't crash on import — the user will see an empty menu.
    print("sslOpenCrypt Nautilus extension: gi.repository.Nautilus not found. "
          "Install python3-nautilus to enable the right-click menu.")
