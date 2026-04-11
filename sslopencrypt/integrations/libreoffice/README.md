# sslOpenCrypt — LibreOffice Integration

Sign, verify, encrypt, and hash LibreOffice documents without leaving the application.

## Architecture

```
LibreOffice Basic macro  ──JSON/TCP──▶  IPC server (localhost:47251)  ──▶  sslOpenCrypt modules
(sslopencrypt_macro.bas)               (ipc_server.py)                      (signing, symmetric…)
```

The IPC server binds **only to 127.0.0.1** — it is not accessible from the network.

## Setup

### 1. Start the IPC server

```bash
# System install
python3 /opt/sslopencrypt/integrations/libreoffice/ipc_server.py &

# User install
python3 ~/.local/lib/sslopencrypt/integrations/libreoffice/ipc_server.py &

# Auto-start via systemd user service (recommended)
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

### 2. Install the LibreOffice macro

1. Open LibreOffice Writer (or Calc, Impress…).
2. Go to **Tools → Macros → Edit Macros…**
3. In the Basic IDE, create a new module: right-click **My Macros** → **Insert Module**.
4. Name it `sslOpenCrypt` and paste the contents of `sslopencrypt_macro.bas`.
5. Close the Basic IDE.

### 3. Assign macros to menu or toolbar

Go to **Tools → Customise**. In the **Menus** or **Toolbars** tab, add entries pointing to the macros:

| Macro name | Suggested label |
|---|---|
| `sslOpenCrypt.Module1.SignDocument` | Sign Document |
| `sslOpenCrypt.Module1.VerifySignature` | Verify Signature |
| `sslOpenCrypt.Module1.HashDocument` | Hash Document |
| `sslOpenCrypt.Module1.EncryptDocument` | Encrypt Document |
| `sslOpenCrypt.Module1.CheckServer` | Check sslOpenCrypt Server |

## Operations

| Operation | Description |
|---|---|
| **Sign** | Creates `<docname>.p7s` CMS/PKCS#7 detached signature |
| **Verify** | Verifies a `.p7s` signature against the document |
| **Hash** | Computes SHA-256 (or chosen algorithm) of the saved document |
| **Encrypt** | Encrypts the document with AES-256-GCM |

## IPC Protocol

The macro communicates with the server via newline-delimited JSON:

**Request:**
```json
{"op": "sign", "file": "/home/user/contract.odt"}
```

**Response:**
```json
{"success": true, "command": "openssl cms ...", "result": "...", "output": "/home/user/contract.odt.p7s", "error": ""}
```

## Security Notes

- The IPC server runs on `127.0.0.1:47251` only — no network exposure.
- Passphrases are passed in the JSON request and are never written to disk or to the audit log.
- All temp files created during operations use `tempfile.mkstemp()` with mode `0o600`.
