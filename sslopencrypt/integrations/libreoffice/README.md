# sslOpenCrypt — LibreOffice Integration

Sign, verify, encrypt, and hash LibreOffice documents with a single keypress — no menu diving, no LibreOffice UI setup required.

## Quick start (zero-configuration)

```bash
# 1. Install keyboard shortcuts (one-time, ~5 seconds)
python3 install_libreoffice.py

# 2. Start the IPC server (keep running in background)
python3 ipc_server.py &
```

That's it. Open any LibreOffice document and use:

| Shortcut | Action |
|---|---|
| **Ctrl+Alt+S** | Sign document (creates `<docname>.p7s`) |
| **Ctrl+Alt+E** | Encrypt document (AES-256-GCM, creates `<docname>.enc`) |
| **Ctrl+Alt+H** | Hash document (SHA-256 digest) |
| **Ctrl+Alt+V** | Verify signature |

Shortcuts work in Writer, Calc, Impress, Draw, and Base.

## Architecture

```
LibreOffice keypress  ─────────▶  Basic macro (Module1.xba)
(Ctrl+Alt+S/E/H/V)               ─JSON/TCP──▶  IPC server (localhost:47251)
                                               ─────────▶  sslOpenCrypt modules
```

The IPC server binds **only to 127.0.0.1** — not accessible from the network.

## What the installer does

`install_libreoffice.py` performs three steps with no user interaction:

1. **Copies macro library** — installs `Module1.xba` and `Setup.xba` to
   `~/.config/libreoffice/4/user/Scripts/basic/sslOpenCrypt/`

2. **Registers shortcuts** — launches LibreOffice headless and runs
   `sslOpenCrypt.Setup.RegisterShortcuts` which calls
   `com.sun.star.ui.GlobalAcceleratorConfiguration` to bind Ctrl+Alt+S/E/H/V

3. **Verifies** — checks that shortcuts were registered successfully

## Auto-start the IPC server on login

```bash
cat > ~/.config/systemd/user/sslopencrypt-ipc.service <<EOF
[Unit]
Description=sslOpenCrypt LibreOffice IPC Server

[Service]
ExecStart=python3 /opt/sslopencrypt/integrations/libreoffice/ipc_server.py
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user enable --now sslopencrypt-ipc
```

## Remove

```bash
python3 install_libreoffice.py --remove
```

This removes the macro library. To clear the keyboard shortcuts:
Tools → Customise → Keyboard → remove the Ctrl+Alt+S/E/H/V bindings.

## Manual installation (alternative)

If the auto-installer doesn't work on your system:

1. Copy `macro_library/` contents to
   `~/.config/libreoffice/4/user/Scripts/basic/sslOpenCrypt/`
2. Open LibreOffice → Tools → Macros → Organise Basic Macros
3. Locate `sslOpenCrypt.Setup.RegisterShortcuts` and run it

## IPC Protocol

**Request:**
```json
{"op": "sign", "file": "/home/user/contract.odt"}
```

**Response:**
```json
{"success": true, "command": "openssl cms ...", "result": "...", "output": "/home/user/contract.odt.p7s", "error": ""}
```

Operations: `sign`, `verify`, `hash`, `encrypt`, `decrypt`

## Security Notes

- IPC server binds to `127.0.0.1:47251` only — no network exposure.
- Passphrases are passed in the JSON request and are never written to disk or to the audit log.
- The active document is auto-saved before any cryptographic operation.
- All temp files use `tempfile.mkstemp()` with mode `0o600`.
