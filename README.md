# sslOpenCrypt

**An open-source GUI for OpenSSL, GnuPG, and PKI — making cryptography visible, learnable, and accessible.**

> *Using sslOpenCrypt is simultaneously using OpenSSL — and learning it.*

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#installation)
[![Stack](https://img.shields.io/badge/stack-Python%20%7C%20PyQt6%20%7C%20OpenSSL-green)](#architecture)

---

## What is sslOpenCrypt?

sslOpenCrypt is a cross-platform, open-source graphical application that puts the full power of OpenSSL — and GnuPG — into a clean, mode-sensitive interface suitable for every skill level.

Its **defining feature** is the live **Command Console**: every action you perform in the GUI produces the exact `openssl` (or `gpg`) command that was run, shown in a panel you can copy, edit, bookmark, and re-run. You learn the CLI by using the GUI.

Built for:
- **Students and educators** — four knowledge levels in every panel: ELI5, Beginner, Intermediate, Expert
- **Developers and sysadmins** — key pairs, CSR generation, CA management, TLS inspection, batch signing
- **Small businesses and NGOs** — document signing, S/MIME email, internal CAs, compliance audit logs
- **Embedded engineers** — EC key generation for OTA firmware signing (Pi Pico 2W / RP2350), PKCS#11 support
- **Indian users** — full support for India's DSC ecosystem: Class 3 USB tokens, Aadhaar eSign API, DigiLocker, MCA21, GSTN, Income Tax portals

---

## Key Features

| Feature | Detail |
|---|---|
| **Live Command Console** | Every GUI operation shows the real `openssl` / `gpg` command. Copy, edit, bookmark, export as `.sh` / `.bat` |
| **Four knowledge levels** | ELI5, Beginner, Intermediate, Expert — switchable per-panel |
| **10 functional modules** | Key management, symmetric crypto, hashing, PKI/X.509, file signing, S/MIME, random generation, TLS advisor, educational hub, GnuPG/OpenPGP |
| **GnuPG integration** | Module 10 wraps `gpg2` for OpenPGP key generation, encryption, signing, keyserver operations |
| **Standalone key vault** | AES-256-GCM encrypted vault, Argon2id key derivation — not dependent on KeePassXC or OS secret service |
| **Expert Mode guardrails** | Deprecated algorithms (MD5, SHA-1, RC4) available with amber-border warning, mandatory confirmation, `DEPRECATED_ALG` audit-log tag |
| **Immutable audit log** | Every cryptographic operation logged locally with timestamp; exportable for compliance evidence |
| **Internationalised from v0.1** | Qt Linguist i18n; Tier 1: Hindi, Tamil, Kannada, Telugu, Malayalam, Bengali; Tier 2: German, Portuguese, Spanish, Japanese |
| **OTA firmware signing** | GUI-guided EC P-256 key generation and `.bin.signed` verification for Pi Pico 2W (RP2350) OTA workflows |
| **Self-contained** | No telemetry, no cloud account, no online licence server; bundles or detects system OpenSSL |

---

## Modules

| # | Module | Core Function |
|---|---|---|
| 1 | **Key Management** | Generate, inspect, convert RSA / ECDSA / Ed25519 / X25519 / DSA key pairs; local encrypted key vault |
| 2 | **Symmetric Encryption** | AES-128/192/256 (CBC, CTR, GCM, CCM), ChaCha20-Poly1305; passphrase or raw-key input |
| 3 | **Hashing & Digests** | SHA-2/3, BLAKE2, MD5 (legacy); HMAC; file verification; avalanche-effect demo |
| 4 | **PKI & Certificates** | CSR builder, self-signed certs, Root/Intermediate CA, CRL, OCSP, chain viewer, TLS inspector |
| 5 | **Document & File Signing** | PKCS#7 / CAdES detached signatures, PAdES for PDF, RFC 3161 timestamps, batch signing |
| 6 | **S/MIME & Email** | Encrypt and sign email bodies; PKCS#12 export for Thunderbird/Outlook; contact certificate book |
| 7 | **Secure Random & Password** | Cryptographically strong random bytes, passwords, UUIDs; entropy meter; DH parameter generation |
| 8 | **TLS Configuration Advisor** | Cipher-suite builder for Nginx/Apache/Postfix; Mozilla-scored rating; live `s_client` inspection |
| 9 | **Educational Hub** | Step-by-step tutorials, animated key-exchange diagrams, Command Explorer, exportable lab reports, quiz mode |
| 10 | **GnuPG / OpenPGP** | Key generation (RSA-4096, Ed25519, Cv25519), encrypt/decrypt, sign/verify, keyserver import/export *(v1.1)* |

---

## Architecture

sslOpenCrypt follows a strict three-layer architecture:

```
┌─────────────────────────────────────────┐
│         UI Layer (PyQt6 / QML)          │
│   Widgets · Dialogs · Command Console   │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│         Controller Layer (Python)        │
│   Validation · State · Parameter build  │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│           Execution Layer               │
│  subprocess → openssl CLI  (primary)    │
│  python-cryptography library (parsing)  │
│  gpg2 subprocess  (Module 10)           │
└─────────────────────────────────────────┘
```

Every execution returns a structured result object containing:
- The exact command run
- stdout / stderr
- Parsed output as a Python dict
- Success / failure status

This object drives both the result panel and the Command Console simultaneously.

### Mode System

| Mode | Description |
|---|---|
| **Beginner** | Command Console hidden; plain-English labels; algorithm choices curated to safe defaults |
| **Expert** | Console visible and editable; all parameters exposed; deprecated algorithms available (with warnings — see below) |
| **Classroom** | Instructor-defined constraints; session logging forced; "Reveal answer" for tutorial exercises |
| **Batch / CLI** | Headless execution via command-line arguments; JSON output; suitable for CI pipelines |

### Deprecated-Algorithm Guardrails (Expert Mode)

When a deprecated algorithm is selected, sslOpenCrypt enforces a five-step sequence before execution:

1. **Amber border** on the algorithm selector — persists for the session
2. **Inline warning banner** — algorithm-specific: collision attacks noted for MD5/SHA-1; RFC 7465 prohibition for RC4
3. **Gated confirmation checkbox** — Execute button disabled until explicitly accepted; resets on every algorithm change
4. **Console annotation** — `# WARNING: MD5 is cryptographically broken` prepended to the generated command
5. **Audit log flag** — entry tagged `DEPRECATED_ALG` with timestamp

---

## Application Integrations

| Integration | Mechanism | Status |
|---|---|---|
| LibreOffice | Basic macro + IPC socket | Planned v1.0 |
| Thunderbird | WebExtension (Manifest V3) + native messaging | Planned v1.1 |
| Gmail | Browser extension (Chrome/Firefox) + native messaging | Planned v1.2 |
| Nautilus / Dolphin | Right-click context menu (Encrypt, Sign, Verify, Hash) | v1.0 (Nautilus) / v1.x |
| VS Code | Extension + IPC — sign/inspect files from Explorer | Community contribution |
| Git | `git config gpg.program` wrapper for commit/tag signing | Community v1.x |

---

## Embedded Systems — Pi Pico 2W / RP2350 OTA Signing

The RP2350 integrates hardware SHA-256, AES-128/256, a hardware TRNG, and ARM TrustZone-M, making it a capable platform for signed OTA firmware delivery. sslOpenCrypt provides the developer-side GUI for the [Earle Philhower Arduino core](https://github.com/earlephilhower/arduino-pico) signing pipeline:

### Signing Chain

```
Developer machine                      Device (RP2350 flash)
────────────────                       ──────────────────────
openssl ecparam                        signing_pubkey[] baked
  -name prime256v1 ──► private.key     in at compile time
  -genkey                              (via signing.py pre-hook)
        │
        ▼
openssl dgst -sha256                   Receives .bin.signed via OTA
  -sign private.key                    Verifies ECDSA signature
  firmware.bin                         against signing_pubkey[]
        │                              PASS → flash swap → reboot
        ▼                              FAIL → reject, unchanged
firmware.bin.signed
(raw binary + 72-byte DER signature
 + 4-byte length marker)
```

### sslOpenCrypt's Role

| Task | Module | What sslOpenCrypt does |
|---|---|---|
| Key pair generation | Module 1 | GUI for `openssl ecparam` + `openssl ec`; private key stored in vault |
| Pre-distribution verification | Module 5 | Verifies `.bin.signed` via `openssl dgst -sha256 -verify`; shows fingerprint and file sizes |
| Key vault storage | Vault | Private key encrypted at rest (AES-256-GCM, Argon2id); export-before-build, delete-after-build workflow |
| Key rotation | Module 1 | Rotation event recorded in audit log with old/new key fingerprints |
| Per-device licence binding | Module 5 | Verifies per-device `.bin.signed` output from `generate_uf2.py` |

**Recommended configuration for embedded signing:**
- Algorithm: ECDSA / EC P-256 (`prime256v1`) — 72-byte signatures vs 256+ bytes for RSA-2048
- Digest: SHA-256 — required by `signing.py` hook
- Vault label convention: `sslopencrypt-signing-[product]-[YYYY]`

---

## Key Design Decisions

### Why `openssl` CLI and not a pure Python library?

The `openssl` CLI is what every server, Docker image, and CI script uses. By calling it as a subprocess and displaying the command, sslOpenCrypt teaches the tool users will encounter everywhere. The `python-cryptography` library is used only for parsing output and in-app educational visualisations.

### Why PyQt6 and not GTK or Electron?

- Single Python codebase for Linux, macOS, and Windows with native look-and-feel on each
- GPL v3 compatible (unlike LGPL PySide6, which has licence implications for derived works)
- Excellent i18n support via Qt Linguist
- Electron carries 150–300 MB runtime overhead and a larger attack surface

### Security of the App Itself

- Private keys are **never** written to `/tmp` or unprotected paths — `tempfile.mkstemp(mode=0o600)` only
- Passphrase fields: no undo history, no clipboard, clear-on-focus-loss option
- Key vault: Argon2id key derivation (resists GPU attacks); no PBKDF2
- No telemetry, no crash reports, no network calls except those the user explicitly initiates
- `openssl` invoked with explicit path; binary hash verified at startup
- All subprocess calls sanitise arguments; **no `shell=True`** anywhere in the codebase

---

## Development Roadmap

| Milestone | Focus |
|---|---|
| **v0.1 Alpha** | Core engine, Command Console, key generation (RSA/ECDSA/Ed25519), symmetric encryption |
| **v0.2 Alpha** | PKI module: CSR builder, CA manager, chain viewer, TLS inspector, file signing |
| **v0.3 Beta** | S/MIME, secure random, TLS advisor, Nautilus extension, Educational Hub tutorials |
| **v1.0 Stable** | LibreOffice integration, Classroom mode, lab report export, AppImage / .dmg / NSIS installers |
| **v1.1** | Thunderbird extension, Module 10 (GnuPG/OpenPGP), OCSP/CRL UI, batch CLI, PKCS#11 / HSM |
| **v1.2** | Gmail extension, PAdES PDF signing, RFC 3161 TSA client, VS Code extension API |
| **v2.x** | Flutter companion app for Android/iOS, hardware token (YubiKey/TPM) support, PQC (ML-KEM/ML-DSA) when mainline OpenSSL PQC ships (expected 2026+) |

---

## Internationalisation

Qt Linguist `.ts` / `.qm` support is built in from v0.1. All strings use `tr()` — no hard-coded English in Python source.

**Tier 1 (India):** Hindi · Tamil · Kannada · Telugu · Malayalam · Bengali  
**Tier 2 (International):** German · Portuguese · Spanish · Japanese

RTL layout support is planned for v1.x.

---

## Funding

The core sslOpenCrypt application is **free and open-source (GPL v3)**.

A **commercial Pro Edition** sustains development. It adds:

- Root CA and Subordinate CA creation
- CRL / OCSP management
- Policy templates (NIST, GDPR, India IT Act compliant presets)
- Batch signing workflows
- Priority e-mail support

**Not included in Pro (out of scope):** Enterprise RA/CA cluster management, HSM-backed CA, SCEP/EST auto-enrolment server, multi-tenant CA portals.

Pro features are activated by an offline licence key. No phone-home. No cloud licence server.

---

## Repository Structure

```
sslopencrypt/
├── core/              — subprocess wrapper, result types, temp-file manager
├── modules/
│   ├── keymgmt/       — Module 1: key generation and vault
│   ├── symmetric/     — Module 2: AES, ChaCha20
│   ├── hashing/       — Module 3: SHA, HMAC, BLAKE2
│   ├── pki/           — Module 4: X.509, CA, CSR
│   ├── signing/       — Module 5: CAdES, PAdES, RFC 3161
│   ├── smime/         — Module 6: S/MIME email
│   ├── random/        — Module 7: CSPRNG, DH params
│   ├── tls/           — Module 8: cipher-suite advisor
│   ├── edu/           — Module 9: tutorials, animations, quiz
│   └── gpg/           — Module 10: GnuPG / OpenPGP
├── ui/                — PyQt6 widgets, main window, dialogs, i18n/
├── integrations/      — LibreOffice macro, browser extensions, file-manager plugins
├── cli/               — headless batch-mode entry point
├── tests/             — pytest suite (unit + integration)
├── docs/              — ReadTheDocs source (reStructuredText)
└── packaging/         — AppImage recipe, .dmg build script, NSIS script
```

---

## Contributing

Areas actively looking for contributors:

| Area | Skills |
|---|---|
| **UI/UX Design** | Figma mockups, icon design, accessibility, dark/light themes |
| **Cryptography Review** | Review module designs for correctness; spot dangerous defaults |
| **Translations** | Qt Linguist `.ts` files for any priority language |
| **Integration Plugins** | VS Code extension, Dolphin KDE plugin, macOS Automator workflows |
| **Educational Content** | Tutorial scripts, animation storyboards, quiz questions, glossary |
| **Build & Packaging** | AppImage, Flatpak, Homebrew formula, Chocolatey, Snap |

Open an issue or start a discussion on GitHub. All contributions licensed under GPL v3.

---

## Documents

| Document | Description |
|---|---|
| [`sslOpenCrypt_Specification_v0.3.docx`](sslOpenCrypt_Specification_v0.3.docx) | Full product specification including architecture, module specs, design decisions, OTA use case |
| [`sslOpenCrypt_Complete_Book_v1.0.docx`](sslOpenCrypt_Complete_Book_v1.0.docx) | Complete reference book — product spec + cryptography reference + India DSC ecosystem guide |

---

## References

| Resource | Link |
|---|---|
| OpenSSL | https://openssl.org |
| PyQt6 | https://riverbankcomputing.com/software/pyqt/ |
| python-cryptography | https://cryptography.io |
| GnuPG | https://gnupg.org |
| endesive (PAdES/CAdES) | https://github.com/m32/endesive |
| OQS-OpenSSL (PQC experimental) | https://github.com/open-quantum-safe/openssl |
| Mozilla SSL Config Generator | https://ssl-config.mozilla.org |
| NIST Post-Quantum Standards | https://csrc.nist.gov/projects/post-quantum-cryptography |
| CCA India PKI | https://cca.gov.in |
| Earle Philhower RP2040/RP2350 core | https://github.com/earlephilhower/arduino-pico |

---

**tctech.co.in · GPL v3 · sslOpenCrypt**
