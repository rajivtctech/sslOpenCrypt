#!/usr/bin/env bash
# sslopencrypt-hash.sh — Compute SHA-256 hash of a file and display with kdialog.
# Called by the Dolphin service menu "Compute SHA-256…" action.
#
# Usage: sslopencrypt-hash.sh <file>

set -euo pipefail

FILE="$1"

if [[ ! -f "$FILE" ]]; then
    kdialog --error "File not found: $FILE" --title "sslOpenCrypt — Error" 2>/dev/null \
        || zenity --error --text="File not found: $FILE" --title="sslOpenCrypt — Error" 2>/dev/null \
        || xmessage "sslOpenCrypt Error: File not found: $FILE"
    exit 1
fi

# Prefer sslOpenCrypt CLI; fall back to openssl directly
DIGEST=""
if command -v sslopencrypt &>/dev/null; then
    # Run in headless/hash mode if supported; otherwise just use openssl
    DIGEST=$(openssl dgst -sha256 "$FILE" 2>/dev/null | awk '{print $NF}')
elif python3 -c "import pathlib; pathlib.Path('$HOME/.local/lib/sslopencrypt/main.py').exists()" 2>/dev/null; then
    DIGEST=$(openssl dgst -sha256 "$FILE" 2>/dev/null | awk '{print $NF}')
else
    DIGEST=$(openssl dgst -sha256 "$FILE" 2>/dev/null | awk '{print $NF}')
fi

if [[ -z "$DIGEST" ]]; then
    MSG="Failed to compute SHA-256 for:\n$FILE"
else
    FNAME=$(basename "$FILE")
    MSG="SHA-256 digest of: $FNAME\n\n$DIGEST"
fi

# Try kdialog first (KDE), then zenity (GNOME), then xmessage
if command -v kdialog &>/dev/null; then
    kdialog --msgbox "$MSG" --title "sslOpenCrypt — SHA-256" 2>/dev/null
elif command -v zenity &>/dev/null; then
    zenity --info --text="$MSG" --title="sslOpenCrypt — SHA-256" 2>/dev/null
elif command -v xmessage &>/dev/null; then
    echo -e "$MSG" | xmessage -file - -title "sslOpenCrypt — SHA-256"
else
    echo "$MSG"
fi
