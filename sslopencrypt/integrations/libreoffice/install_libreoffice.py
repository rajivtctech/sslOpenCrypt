#!/usr/bin/env python3
"""
install_libreoffice.py — Zero-configuration sslOpenCrypt LibreOffice installer.

Installs the sslOpenCrypt macro library into the user's LibreOffice profile
and registers four global keyboard shortcuts — all without opening LibreOffice
or requiring any interaction.

After running this installer, the following shortcuts work in any LibreOffice
document (Writer, Calc, Impress, Draw) immediately:

    Ctrl+Alt+S  →  Sign document
    Ctrl+Alt+E  →  Encrypt document (AES-256-GCM)
    Ctrl+Alt+H  →  Hash document (SHA-256)
    Ctrl+Alt+V  →  Verify signature

Usage:
    python3 install_libreoffice.py [--remove]

Requirements:
    - LibreOffice (soffice must be on PATH or in /usr/bin/)
    - The sslOpenCrypt IPC server for runtime operations:
        python3 /opt/sslopencrypt/integrations/libreoffice/ipc_server.py &
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
MACRO_LIB_SRC = SCRIPT_DIR / "macro_library"
LIBRARY_NAME = "sslOpenCrypt"

SHORTCUTS = [
    ("Ctrl+Alt+S", "SignDocument"),
    ("Ctrl+Alt+E", "EncryptDocument"),
    ("Ctrl+Alt+H", "HashDocument"),
    ("Ctrl+Alt+V", "VerifySignature"),
]


def find_lo_profile() -> Path | None:
    """Return the LibreOffice user profile directory, or None if not found."""
    candidates = [
        Path.home() / ".config" / "libreoffice" / "4" / "user",
        Path.home() / ".libreoffice" / "4" / "user",
    ]
    # Also check version directories other than 4
    base = Path.home() / ".config" / "libreoffice"
    if base.exists():
        for version_dir in sorted(base.iterdir(), reverse=True):
            candidate = version_dir / "user"
            if candidate.is_dir():
                candidates.insert(0, candidate)

    for c in candidates:
        if c.is_dir():
            return c
    return None


def find_soffice() -> str | None:
    """Return the path to the soffice binary, or None if not found."""
    soffice = shutil.which("soffice")
    if soffice:
        return soffice
    for p in ["/usr/bin/soffice", "/usr/lib/libreoffice/program/soffice"]:
        if Path(p).exists():
            return p
    return None


def lo_profile_or_die() -> Path:
    profile = find_lo_profile()
    if profile:
        return profile
    # LibreOffice may not have been run yet — create the minimal directory
    default = Path.home() / ".config" / "libreoffice" / "4" / "user"
    default.mkdir(parents=True, exist_ok=True)
    print(f"  Created LO profile directory: {default}")
    return default


def macro_dest(profile: Path) -> Path:
    return profile / "Scripts" / "basic" / LIBRARY_NAME


# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

def install(profile: Path, soffice: str) -> int:
    dest = macro_dest(profile)
    print(f"  LibreOffice profile : {profile}")
    print(f"  Macro library dest  : {dest}")
    print(f"  soffice binary      : {soffice}")
    print()

    # 1. Copy XBA files and icons/
    print("Step 1/3 — Copying macro library files…")
    dest.mkdir(parents=True, exist_ok=True)
    for src_file in MACRO_LIB_SRC.iterdir():
        dst_file = dest / src_file.name
        if src_file.is_dir():
            if dst_file.exists():
                shutil.rmtree(dst_file)
            shutil.copytree(src_file, dst_file)
            icon_count = sum(1 for _ in dst_file.iterdir())
            print(f"  Copied: {dst_file.name}/  ({icon_count} files)")
        else:
            shutil.copy2(src_file, dst_file)
            print(f"  Copied: {dst_file.name}")

    # 2. Register library in the LO user profile (registrymodifications.xcu)
    #    LibreOffice auto-discovers libraries in Scripts/basic/ — no XCU edit needed.
    print()
    print("Step 2/3 — Registering keyboard shortcuts via headless LibreOffice…")

    # Remove any stale marker file
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
    marker = Path(xdg_runtime) / "sslopencrypt_shortcuts_registered"
    marker.unlink(missing_ok=True)

    macro_url = f"macro:///{LIBRARY_NAME}.Setup.RegisterShortcuts"
    cmd = [
        soffice,
        "--headless",
        "--norestore",
        "--nofirststartwizard",
        "--nologo",
        macro_url,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Wait up to 30 seconds for the macro to finish and LO to exit
        for _ in range(60):
            time.sleep(0.5)
            if marker.exists():
                break
            if proc.poll() is not None:
                break

        # Give it a moment to flush
        time.sleep(0.5)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    except FileNotFoundError:
        print(f"  ERROR: soffice not found at {soffice}")
        return 1

    # 3. Check marker file
    print()
    print("Step 3/3 — Verifying shortcut registration…")
    if marker.exists():
        content = marker.read_text().strip()
        if content.startswith("ERROR"):
            print(f"  WARNING: Macro reported an error: {content}")
            print("  Shortcuts may not be registered. Try opening LibreOffice and")
            print("  running Tools → Macros → sslOpenCrypt.Setup.RegisterShortcuts manually.")
            return 1
        else:
            print(f"  Shortcuts registered successfully:")
            for line in content.splitlines()[1:]:
                print(f"    {line}")
    else:
        # LO may have registered shortcuts without writing the marker (LO version quirk)
        print("  Note: marker file not found — LibreOffice may have exited before writing it.")
        print("  Shortcuts are likely registered. Open LibreOffice to verify.")
        print("  (Tools → Macros → Organise Basic Macros → sslOpenCrypt)")

    print()
    print("Installation complete.")
    print()
    print("Keyboard shortcuts active in all LibreOffice documents:")
    for shortcut, macro in SHORTCUTS:
        print(f"    {shortcut}  →  {macro}")
    print()
    print("Toolbar: View → Toolbars → sslOpenCrypt (Writer / Calc / Impress / Draw)")
    print()
    print("The IPC server must be running for shortcuts to work:")
    print(f"    python3 {SCRIPT_DIR}/ipc_server.py &")
    print()
    print("To auto-start the server on login, see the systemd example in README.md.")
    return 0


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------

def remove(profile: Path) -> int:
    dest = macro_dest(profile)
    if dest.exists():
        shutil.rmtree(dest)
        print(f"  Removed: {dest}")
    else:
        print(f"  Nothing to remove (not installed at {dest})")

    print()
    print("Note: keyboard shortcuts registered with GlobalAcceleratorConfiguration")
    print("persist in the LibreOffice user profile. To clear them, open LibreOffice,")
    print("go to Tools → Customise → Keyboard, and remove the Ctrl+Alt+S/E/H/V bindings.")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Install or remove sslOpenCrypt LibreOffice integration"
    )
    parser.add_argument(
        "--remove", action="store_true",
        help="Remove the macro library (keyboard shortcuts must be cleared manually)"
    )
    args = parser.parse_args()

    print("sslOpenCrypt — LibreOffice Integration Installer")
    print("=" * 50)
    print()

    profile = lo_profile_or_die()

    if args.remove:
        return remove(profile)

    soffice = find_soffice()
    if not soffice:
        print("ERROR: LibreOffice (soffice) not found on PATH.")
        print("Install LibreOffice first: sudo apt install libreoffice")
        return 1

    if not MACRO_LIB_SRC.is_dir():
        print(f"ERROR: macro_library/ directory not found at {MACRO_LIB_SRC}")
        return 1

    return install(profile, soffice)


if __name__ == "__main__":
    sys.exit(main())
