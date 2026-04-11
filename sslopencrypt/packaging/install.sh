#!/usr/bin/env bash
# install.sh — Install sslOpenCrypt on Linux (system-wide or user)
# Usage:
#   sudo bash install.sh          # system-wide (/opt/sslopencrypt, /usr/local/bin)
#   bash install.sh --user        # user install (~/.local/...)

set -euo pipefail

INSTALL_DIR="/opt/sslopencrypt"
BIN_DIR="/usr/local/bin"
DESKTOP_DIR="/usr/share/applications"
ICON_DIR="/usr/share/pixmaps"
USER_INSTALL=false

for arg in "$@"; do
    [[ "$arg" == "--user" ]] && USER_INSTALL=true
done

if [[ "$USER_INSTALL" == "true" ]]; then
    INSTALL_DIR="$HOME/.local/lib/sslopencrypt"
    BIN_DIR="$HOME/.local/bin"
    DESKTOP_DIR="$HOME/.local/share/applications"
    ICON_DIR="$HOME/.local/share/pixmaps"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

echo "Installing sslOpenCrypt to $INSTALL_DIR ..."

# Install application files
mkdir -p "$INSTALL_DIR"
cp -r "$REPO_DIR"/{main.py,core,modules,ui,cli,requirements.txt} "$INSTALL_DIR/"

# Create launcher script
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/sslopencrypt" <<EOF
#!/usr/bin/env bash
exec python3 "$INSTALL_DIR/main.py" "\$@"
EOF
chmod +x "$BIN_DIR/sslopencrypt"

# Install desktop entry
mkdir -p "$DESKTOP_DIR"
sed "s|/opt/sslopencrypt|$INSTALL_DIR|g" "$SCRIPT_DIR/sslopencrypt.desktop" \
    > "$DESKTOP_DIR/sslopencrypt.desktop"

# Install Python dependencies
python3 -m pip install --quiet PyQt6 cryptography argon2-cffi ${USER_INSTALL:+--user}

echo ""
echo "✓  sslOpenCrypt 1.0.0 installed successfully."
echo "   Launch: sslopencrypt"
echo "   Or: $INSTALL_DIR/main.py"
