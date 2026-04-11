#!/usr/bin/env bash
# install.sh — Install sslOpenCrypt Nautilus (GNOME) / Nemo (Cinnamon) extension.
#
# Usage:
#   bash install.sh          # install
#   bash install.sh --remove # remove

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_FILE="sslopencrypt-nautilus.py"

NAUTILUS_EXT_DIR="$HOME/.local/share/nautilus-python/extensions"
NEMO_EXT_DIR="$HOME/.local/share/nemo-python/extensions"

# ── Remove mode ──────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--remove" ]]; then
    echo "Removing sslOpenCrypt Nautilus/Nemo extension…"
    rm -f "$NAUTILUS_EXT_DIR/$EXT_FILE"
    rm -f "$NEMO_EXT_DIR/sslopencrypt-nemo.py"
    echo "Restarting Nautilus…"
    nautilus -q 2>/dev/null || true
    echo "Done."
    exit 0
fi

# ── Install mode ──────────────────────────────────────────────────────────────
echo "Installing sslOpenCrypt Nautilus extension…"

# Nautilus
mkdir -p "$NAUTILUS_EXT_DIR"
cp "$SCRIPT_DIR/$EXT_FILE" "$NAUTILUS_EXT_DIR/$EXT_FILE"
echo "  Copied: $NAUTILUS_EXT_DIR/$EXT_FILE"

# Nemo (if python3-nemo is installed)
if python3 -c "from gi.repository import Nemo" 2>/dev/null; then
    mkdir -p "$NEMO_EXT_DIR"
    cp "$SCRIPT_DIR/$EXT_FILE" "$NEMO_EXT_DIR/sslopencrypt-nemo.py"
    echo "  Copied: $NEMO_EXT_DIR/sslopencrypt-nemo.py"
fi

# Restart Nautilus
echo "  Restarting Nautilus…"
nautilus -q 2>/dev/null || true

echo ""
echo "Installation complete."
echo "Right-click any file in Nautilus → sslOpenCrypt to use."
echo ""
echo "Note: If the menu doesn't appear, ensure python3-nautilus is installed:"
echo "  sudo apt install python3-nautilus"
