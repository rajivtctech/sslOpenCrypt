# sslOpenCrypt — Dolphin (KDE) Integration

Right-click context menu for Dolphin and Konqueror file managers.

## Operations available

| Menu item | Action |
|---|---|
| Sign File… | Opens sslOpenCrypt Document Signing module pre-loaded with the selected file |
| Verify Signature… | Opens sslOpenCrypt Document Signing module |
| Encrypt… | Opens sslOpenCrypt Symmetric Encryption module |
| Decrypt… | Opens sslOpenCrypt Symmetric Encryption module |
| Compute SHA-256… | Computes SHA-256 hash and shows the result in a kdialog popup |

## Installation

```bash
bash install.sh
```

That's it. The installer:
1. Creates `~/.local/share/kio/servicemenus/` if absent
2. Copies the `.desktop` service menu file
3. Copies the `sslopencrypt-hash.sh` helper script
4. Runs `kbuildsycoca5` to rebuild KDE's service cache

## Removal

```bash
bash install.sh --remove
```

## Requirements

- KDE Plasma (Dolphin / Konqueror)
- sslOpenCrypt installed (either `sslopencrypt` on PATH, or at `~/.local/lib/sslopencrypt/` or `/opt/sslopencrypt/`)
- `kdialog` for SHA-256 result popup (included in most KDE installs)

## For Konqueror

The same `.desktop` file works for Konqueror — it reads from the same
`~/.local/share/kio/servicemenus/` directory.
