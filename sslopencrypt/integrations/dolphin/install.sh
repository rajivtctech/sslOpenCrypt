#!/usr/bin/env bash
# install.sh — Install sslOpenCrypt Dolphin service menu.
#
# Installs the right-click context menu for KDE Dolphin and Konqueror.
# Safe to run multiple times (idempotent).
#
# Usage:
#   bash install.sh          # install
#   bash install.sh --remove # remove

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICEMENU_DIR="$HOME/.local/share/kio/servicemenus"
DESKTOP_FILE="sslopencrypt.desktop"
HASH_SCRIPT="sslopencrypt-hash.sh"

# ── Remove mode ─────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--remove" ]]; then
    echo "Removing sslOpenCrypt Dolphin integration…"
    rm -f "$SERVICEMENU_DIR/$DESKTOP_FILE"
    rm -f "$SERVICEMENU_DIR/$HASH_SCRIPT"
    if command -v kbuildsycoca5 &>/dev/null; then
        kbuildsycoca5 --noincremental 2>/dev/null || true
    fi
    echo "Done. Restart Dolphin to see the change."
    exit 0
fi

# ── Install mode ─────────────────────────────────────────────────────────────
echo "Installing sslOpenCrypt Dolphin service menu…"

# 1. Create service menu directory if absent
mkdir -p "$SERVICEMENU_DIR"

# 2. Copy the .desktop file
cp "$SCRIPT_DIR/$DESKTOP_FILE" "$SERVICEMENU_DIR/$DESKTOP_FILE"
echo "  Copied: $SERVICEMENU_DIR/$DESKTOP_FILE"

# 3. Copy the hash helper script and make it executable
cp "$SCRIPT_DIR/$HASH_SCRIPT" "$SERVICEMENU_DIR/$HASH_SCRIPT"
chmod +x "$SERVICEMENU_DIR/$HASH_SCRIPT"
echo "  Copied: $SERVICEMENU_DIR/$HASH_SCRIPT"

# 4. Rebuild KDE's sycoca cache so Dolphin picks up the new entry immediately
if command -v kbuildsycoca5 &>/dev/null; then
    echo "  Rebuilding KDE service cache (kbuildsycoca5)…"
    kbuildsycoca5 --noincremental 2>/dev/null || true
elif command -v kbuildsycoca6 &>/dev/null; then
    echo "  Rebuilding KDE service cache (kbuildsycoca6)…"
    kbuildsycoca6 --noincremental 2>/dev/null || true
else
    echo "  Note: kbuildsycoca5/6 not found — you may need to log out and back in."
fi

echo ""
echo "Installation complete."
echo "Right-click any file in Dolphin → sslOpenCrypt to see the menu."
echo ""
echo "If the submenu doesn't appear immediately, restart Dolphin:"
echo "  dolphin --quit; dolphin &"
