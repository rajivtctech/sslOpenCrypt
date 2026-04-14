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

# ---------------------------------------------------------------------------
# Toolbar XML templates (written directly to the user profile — more reliable
# than the headless macro UNO API, which often silently fails to flush)
# ---------------------------------------------------------------------------

# LO module IDs → (human label, WindowState schema name)
# Schema names come from writer/calc/impress/draw.xcd compiled registries.
_TB_MODULES = [
    ("swriter",  "Writer",  "WriterWindowState"),
    ("scalc",    "Calc",    "CalcWindowState"),
    ("simpress", "Impress", "ImpressWindowState"),
    ("sdraw",    "Draw",    "DrawWindowState"),
]

# XCU path template for one toolbar node in a module's window state
_XCU_PATH_TMPL = (
    "/org.openoffice.Office.UI.{ws}/UIElements/States/"
    "org.openoffice.Office.UI.WindowState:WindowStateType"
    "['private:resource/toolbar/sslopencrypt']"
)

# registrymodifications.xcu skeleton — created only when it doesn't exist yet
_XCU_SKELETON = """\
<?xml version="1.0" encoding="UTF-8"?>
<oor:items xmlns:oor="http://openoffice.org/2001/registry"
           xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
</oor:items>
"""

_TOOLBAR_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE toolbar:toolbar PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "toolbar.dtd">
<toolbar:toolbar xmlns:toolbar="http://openoffice.org/2001/toolbar"
                 xmlns:xlink="http://www.w3.org/1999/xlink"
                 toolbar:id="toolbar"
                 toolbar:uiname="sslOpenCrypt">
 <toolbar:toolbaritem xlink:href="macro:///sslOpenCrypt.Module1.SignDocument"
                      toolbar:visible="true"/>
 <toolbar:toolbaritem xlink:href="macro:///sslOpenCrypt.Module1.EncryptDocument"
                      toolbar:visible="true"/>
 <toolbar:toolbaritem xlink:href="macro:///sslOpenCrypt.Module1.HashDocument"
                      toolbar:visible="true"/>
 <toolbar:toolbaritem xlink:href="macro:///sslOpenCrypt.Module1.VerifySignature"
                      toolbar:visible="true"/>
</toolbar:toolbar>
"""

_MANIFEST_ENTRY = (
    ' <manifest:file-entry manifest:media-type="application/vnd.sun.star.toolbar"'
    ' manifest:full-path="toolbar/sslopencrypt.xml"/>'
)

_MANIFEST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE manifest:manifest PUBLIC "-//OpenOffice.org//DTD Manifest 1.0//EN" "Manifest.dtd">
<manifest:manifest xmlns:manifest="http://openoffice.org/2001/manifest">
{entry}
</manifest:manifest>
"""


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


def _cfg_base(profile: Path) -> Path:
    return profile / "config" / "soffice.cfg" / "modules"


# ---------------------------------------------------------------------------
# Toolbar XML helpers
# ---------------------------------------------------------------------------

def _install_toolbar_xml(profile: Path):
    """Write sslopencrypt.xml into each module's toolbar directory and update
    (or create) the per-module manifest.xml so LO discovers the toolbar on
    the next startup.  This is more reliable than the headless UNO API."""
    base = _cfg_base(profile)
    ok = []
    for module_id, module_name, _ws in _TB_MODULES:
        tb_dir = base / module_id / "toolbar"
        tb_dir.mkdir(parents=True, exist_ok=True)

        # Write toolbar definition
        (tb_dir / "sslopencrypt.xml").write_text(_TOOLBAR_XML, encoding="utf-8")

        # Update or create manifest.xml for this module
        mf = base / module_id / "manifest.xml"
        if mf.exists():
            content = mf.read_text(encoding="utf-8")
            if "sslopencrypt.xml" not in content:
                content = content.replace(
                    "</manifest:manifest>",
                    f"{_MANIFEST_ENTRY}\n</manifest:manifest>",
                )
                mf.write_text(content, encoding="utf-8")
        else:
            mf.write_text(
                _MANIFEST_TEMPLATE.format(entry=_MANIFEST_ENTRY),
                encoding="utf-8",
            )
        ok.append(module_name)

    print(f"  Toolbar XML written for: {', '.join(ok)}")


def _install_window_state(profile: Path):
    """Register the toolbar in registrymodifications.xcu so it appears in
    View → Toolbars.  LO uses WindowStateType entries to build that menu —
    toolbar XML files alone are not enough."""
    xcu = profile / "registrymodifications.xcu"
    if xcu.exists():
        content = xcu.read_text(encoding="utf-8")
        if "sslopencrypt" in content:
            print("  Window state already registered.")
            return
    else:
        content = _XCU_SKELETON

    new_items = []
    for _module_id, module_name, ws in _TB_MODULES:
        path = _XCU_PATH_TMPL.format(ws=ws)
        # UIName → display label in View → Toolbars
        new_items.append(
            f'<item oor:path="{path}/UIName">'
            f'<value xml:lang="en-US">sslOpenCrypt</value></item>'
        )
        # Visible=false — hidden by default; user enables via View → Toolbars
        new_items.append(
            f'<item oor:path="{path}">'
            f'<prop oor:name="Visible" oor:op="fuse"><value>false</value></prop></item>'
        )

    block = "\n".join(new_items)
    content = content.replace("</oor:items>", block + "\n</oor:items>")
    xcu.write_text(content, encoding="utf-8")
    print(f"  Window state registered for: {', '.join(m for _, m, _ in _TB_MODULES)}")


def _remove_toolbar_xml(profile: Path):
    """Remove sslopencrypt.xml and its manifest entry from every module."""
    base = _cfg_base(profile)
    for module_id, _name, _ws in _TB_MODULES:
        tb_file = base / module_id / "toolbar" / "sslopencrypt.xml"
        tb_file.unlink(missing_ok=True)

        mf = base / module_id / "manifest.xml"
        if mf.exists():
            lines = mf.read_text(encoding="utf-8").splitlines(keepends=True)
            cleaned = [l for l in lines if "sslopencrypt.xml" not in l]
            mf.write_text("".join(cleaned), encoding="utf-8")


def _remove_window_state(profile: Path):
    """Remove sslopencrypt WindowState entries from registrymodifications.xcu."""
    xcu = profile / "registrymodifications.xcu"
    if not xcu.exists():
        return
    lines = xcu.read_text(encoding="utf-8").splitlines(keepends=True)
    cleaned = [l for l in lines if "sslopencrypt" not in l]
    xcu.write_text("".join(cleaned), encoding="utf-8")


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
    print("Step 1/4 — Copying macro library files…")
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

    # 2. Write toolbar XML files.
    #    sslopencrypt.xml in each module's toolbar/ dir defines the buttons.
    #    The WindowStateType entries that make it appear in View → Toolbars are
    #    written in Step 4, AFTER the headless soffice run — because soffice
    #    reads registrymodifications.xcu into memory on startup and rewrites the
    #    entire file on exit, which would overwrite anything we add before it runs.
    print()
    print("Step 2/4 — Installing toolbar XML (Writer / Calc / Impress / Draw)…")
    _install_toolbar_xml(profile)

    # 3. Register library in the LO user profile (registrymodifications.xcu)
    #    LibreOffice auto-discovers libraries in Scripts/basic/ — no XCU edit needed.
    print()
    print("Step 3/4 — Registering keyboard shortcuts via headless LibreOffice…")

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

    # 4. Register toolbar in window state + verify shortcuts.
    #    Written HERE, after soffice has exited and flushed its copy of
    #    registrymodifications.xcu.  Writing before soffice runs would be
    #    silently wiped out when LO rewrites the file on exit.
    print()
    print("Step 4/4 — Registering toolbar in View → Toolbars menu…")
    _install_window_state(profile)

    print()
    print("Step 4b/4 — Verifying shortcut registration…")
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
    print("Toolbar: restart LibreOffice, then use")
    print("  View → Toolbars → sslOpenCrypt  (Writer / Calc / Impress / Draw)")
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
    # Remove macro library
    dest = macro_dest(profile)
    if dest.exists():
        shutil.rmtree(dest)
        print(f"  Removed macro library: {dest}")
    else:
        print(f"  Macro library not present at {dest}")

    # Remove toolbar XML files from all modules
    _remove_toolbar_xml(profile)
    print("  Removed toolbar XML from Writer / Calc / Impress / Draw")

    # Remove window state entries so toolbar disappears from View → Toolbars
    _remove_window_state(profile)
    print("  Removed window state entries from registrymodifications.xcu")

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
