#!/usr/bin/env bash
# packaging/build_appimage.sh — Build sslOpenCrypt-Linux.AppImage
#
# Usage (run from the sslopencrypt/ project root):
#   bash packaging/build_appimage.sh
#
# Output:
#   dist/sslOpenCrypt-Linux.AppImage   — single executable, chmod +x to run
#
# Requirements on the build machine:
#   - Python 3.10+  with all dependencies installed (pip install -r requirements.txt)
#   - PyInstaller   (pip install pyinstaller)
#   - FUSE          (apt install libfuse2  — needed by appimagetool at build time)
#
# The resulting AppImage runs on any Linux with glibc ≥ 2.17 and FUSE 2.
# It does NOT require Python, PyInstaller, or any other build dependency on the
# end-user machine.  OpenSSL must be installed on the host (openssl ≥ 3.0).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
APPIMAGE_OUT="${PROJECT_DIR}/dist/sslOpenCrypt-Linux.AppImage"
PYINSTALLER_DIST="${PROJECT_DIR}/dist/sslOpenCrypt-Linux"
APPDIR="${PROJECT_DIR}/dist/AppDir"
APPIMAGETOOL_URL="https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage"
APPIMAGETOOL_CACHE="/tmp/appimagetool-x86_64.AppImage"

cd "$PROJECT_DIR"

# ---------------------------------------------------------------------------
# Step 1 — PyInstaller one-directory build
# ---------------------------------------------------------------------------
echo ">>> [1/4] Running PyInstaller (one-dir mode for Linux)…"
python3 -m PyInstaller packaging/sslopencrypt.spec --noconfirm

if [[ ! -d "$PYINSTALLER_DIST" ]]; then
    echo "ERROR: PyInstaller output not found at $PYINSTALLER_DIST"
    exit 1
fi
echo "    PyInstaller output: $PYINSTALLER_DIST"

# ---------------------------------------------------------------------------
# Step 2 — Assemble the AppDir
# ---------------------------------------------------------------------------
echo ">>> [2/4] Assembling AppDir…"
rm -rf "$APPDIR"
mkdir -p "$APPDIR"

# All PyInstaller output files go directly into AppDir root.
# The main binary (sslOpenCrypt-Linux) is at the top level; AppRun execs it.
cp -r "${PYINSTALLER_DIST}/." "$APPDIR/"

# AppImage metadata files
cp "${SCRIPT_DIR}/AppDir/AppRun"             "$APPDIR/AppRun"
cp "${SCRIPT_DIR}/AppDir/sslopencrypt.desktop" "$APPDIR/sslopencrypt.desktop"
cp "${SCRIPT_DIR}/AppDir/sslopencrypt.png"   "$APPDIR/sslopencrypt.png"

# AppRun must be executable
chmod +x "$APPDIR/AppRun"
chmod +x "$APPDIR/sslOpenCrypt-Linux"

echo "    AppDir assembled at: $APPDIR"

# ---------------------------------------------------------------------------
# Step 3 — Obtain appimagetool
# ---------------------------------------------------------------------------
echo ">>> [3/4] Locating appimagetool…"
if command -v appimagetool &>/dev/null; then
    APPIMAGETOOL_BIN="$(command -v appimagetool)"
    echo "    Found system appimagetool: $APPIMAGETOOL_BIN"
elif [[ -x "$APPIMAGETOOL_CACHE" ]]; then
    APPIMAGETOOL_BIN="$APPIMAGETOOL_CACHE"
    echo "    Using cached appimagetool: $APPIMAGETOOL_BIN"
else
    echo "    Downloading appimagetool from GitHub…"
    if command -v wget &>/dev/null; then
        wget -q --show-progress "$APPIMAGETOOL_URL" -O "$APPIMAGETOOL_CACHE"
    else
        curl -L --progress-bar "$APPIMAGETOOL_URL" -o "$APPIMAGETOOL_CACHE"
    fi
    chmod +x "$APPIMAGETOOL_CACHE"
    APPIMAGETOOL_BIN="$APPIMAGETOOL_CACHE"
    echo "    Downloaded to: $APPIMAGETOOL_BIN"
fi

# ---------------------------------------------------------------------------
# Step 4 — Build the AppImage
# ---------------------------------------------------------------------------
echo ">>> [4/4] Building AppImage…"
ARCH=x86_64 "$APPIMAGETOOL_BIN" "$APPDIR" "$APPIMAGE_OUT"

if [[ ! -f "$APPIMAGE_OUT" ]]; then
    echo "ERROR: AppImage not produced at $APPIMAGE_OUT"
    exit 1
fi

chmod +x "$APPIMAGE_OUT"
SIZE_MB=$(du -sh "$APPIMAGE_OUT" | cut -f1)

echo ""
echo "✓  Built successfully:"
echo "   $APPIMAGE_OUT  (${SIZE_MB})"
echo ""
echo "   To run from a USB pendrive:"
echo "     chmod +x sslOpenCrypt-Linux.AppImage"
echo "     ./sslOpenCrypt-Linux.AppImage"
echo ""
echo "   CLI mode:"
echo "     ./sslOpenCrypt-Linux.AppImage --cli --mode <mode>"
