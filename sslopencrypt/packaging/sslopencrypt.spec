# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for sslOpenCrypt
#
# Build (run from the sslopencrypt/ directory):
#   pyinstaller packaging/sslopencrypt.spec
#
# Output: dist/sslOpenCrypt  (Linux/macOS)  or  dist/sslOpenCrypt.exe  (Windows)
#
# NOTE: openssl and gpg are system binaries invoked via subprocess — they are NOT
# bundled. Users must have OpenSSL and (optionally) GnuPG installed on their system.

import os
import sys

# SPECPATH is the directory containing this spec file (sslopencrypt/packaging/)
APP_ROOT = os.path.abspath(os.path.join(SPECPATH, '..'))
MAIN_SCRIPT = os.path.join(APP_ROOT, 'main.py')

# Per-platform executable name
if sys.platform == 'win32':
    EXE_NAME = 'sslOpenCrypt-Windows'
elif sys.platform == 'darwin':
    EXE_NAME = 'sslOpenCrypt-macOS'
else:
    EXE_NAME = 'sslOpenCrypt-Linux'

block_cipher = None

hidden_imports = [
    # Core
    'core',
    'core.audit_log',
    'core.executor',
    'core.result',
    'core.session_log',
    'core.tempfile_manager',
    'core.lab_report',
    # CLI
    'cli',
    'cli.main',
    # UI
    'ui',
    'ui.main_window',
    'ui.app_state',
    'ui.sidebar',
    'ui.command_console',
    'ui.panels',
    'ui.panels.base_panel',
    'ui.panels.keymgmt_panel',
    'ui.panels.symmetric_panel',
    'ui.panels.hashing_panel',
    'ui.panels.pki_panel',
    'ui.panels.signing_panel',
    'ui.panels.smime_panel',
    'ui.panels.random_panel',
    'ui.panels.tls_panel',
    'ui.panels.edu_panel',
    'ui.panels.gpg_panel',
    'ui.panels.vault_panel',
    'ui.panels.india_dsc_panel',
    'ui.panels.integrations_panel',
    # Modules
    'modules',
    'modules.keymgmt',
    'modules.keymgmt.controller',
    'modules.pki',
    'modules.pki.controller',
    'modules.symmetric',
    'modules.symmetric.controller',
    'modules.symmetric.ghost_crypt',
    'modules.hashing',
    'modules.hashing.controller',
    'modules.signing',
    'modules.signing.controller',
    'modules.smime',
    'modules.smime.controller',
    'modules.vault',
    'modules.vault.controller',
    'modules.random',
    'modules.random.controller',
    'modules.tls',
    'modules.tls.controller',
    'modules.gpg',
    'modules.gpg.controller',
    'modules.india_dsc',
    'modules.india_dsc.controller',
    'modules.edu',
    # Third-party
    'argon2',
    'argon2._utils',
    'argon2.low_level',
    'argon2._password_hasher',
    'cffi',
    '_cffi_backend',
    'cryptography',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.backends',
    'cryptography.hazmat.backends.openssl',
    'cryptography.x509',
    'cryptography.x509.extensions',
    # pyhanko — PAdES/CAdES PDF signing (Module 10 India DSC)
    'pyhanko',
    'pyhanko.sign',
    'pyhanko.sign.signers',
    'pyhanko.sign.signers.functions',
    'pyhanko.sign.signers.pdf_signer',
    'pyhanko.sign.fields',
    'pyhanko.sign.pkcs11',
    'pyhanko.sign.timestamps',
    'pyhanko.sign.timestamps.api',
    'pyhanko.pdf_utils',
    'pyhanko.pdf_utils.incremental_writer',
    'pyhanko_certvalidator',
    # python-pkcs11 — PKCS#11 hardware token (optional; graceful degradation if absent)
    'pkcs11',
    'pkcs11.types',
    'pkcs11.mechanisms',
    'pkcs11.exceptions',
    # lxml — required by pyhanko for PDF/XML processing
    'lxml',
    'lxml.etree',
    # oscrypto — required by pyhanko-certvalidator
    'oscrypto',
    'oscrypto.asymmetric',
]

a = Analysis(
    [MAIN_SCRIPT],
    pathex=[APP_ROOT],
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'pytest',
        'pytest_qt',
        'tests',
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=EXE_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=True keeps CLI mode working on all platforms.
    # On Windows this means a console window appears briefly when launching
    # the GUI by double-click — acceptable for a developer/admin tool.
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
