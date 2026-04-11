# sslOpenCrypt — Nautilus Extension

Right-click context menu integration for the Nautilus (GNOME) and Nemo (Cinnamon) file managers.

## Operations available

| Menu item | Action |
|---|---|
| Encrypt… | Opens sslOpenCrypt Symmetric Encryption module pre-loaded with the selected file |
| Decrypt… | Opens sslOpenCrypt Symmetric Encryption module |
| Sign… | Opens sslOpenCrypt Document Signing module |
| Verify Signature… | Opens sslOpenCrypt Document Signing module |
| Compute SHA-256… | Computes SHA-256 hash inline and shows result in a dialog |

## Installation

```bash
# Install the Nautilus Python bindings
sudo apt install python3-nautilus

# Install the extension
mkdir -p ~/.local/share/nautilus-python/extensions/
cp sslopencrypt-nautilus.py ~/.local/share/nautilus-python/extensions/

# Restart Nautilus
nautilus -q && nautilus &
```

## For Nemo (Cinnamon)

```bash
sudo apt install python3-nemo
mkdir -p ~/.local/share/nemo-python/extensions/
cp sslopencrypt-nautilus.py ~/.local/share/nemo-python/extensions/sslopencrypt-nemo.py
nemo -q && nemo &
```

## Requirements

- sslOpenCrypt installed (either `sslopencrypt` on PATH, or at `~/.local/lib/sslopencrypt/` or `/opt/sslopencrypt/`)
- `python3-nautilus` package
- Optional: `zenity` for inline SHA-256 result dialogs (`sudo apt install zenity`)
