"""
ui/panels/gpg_panel.py — Module 10: GnuPG / OpenPGP panel.

Four tabs:
  1. Generate Key  — batch key generation (RSA-4096, Ed25519, Cv25519)
  2. Key Ring      — list public/secret keys, import/export .asc files
  3. Encrypt/Decrypt — file encryption for recipients
  4. Sign/Verify   — detached/inline GPG signatures
"""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout,
    QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QSizePolicy, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from .base_panel import BasePanel


# ---------------------------------------------------------------------------
# Tab 1: Generate Key
# ---------------------------------------------------------------------------

class _GenerateKeyTab(QWidget):
    def __init__(self, panel: "GPGPanel", parent=None):
        super().__init__(parent)
        self._panel = panel
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        grp = QGroupBox("Generate OpenPGP Key Pair")
        form = QFormLayout(grp)
        form.setSpacing(8)

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("Your Name")
        form.addRow("Name:", self._name_edit)

        self._email_edit = QLineEdit()
        self._email_edit.setPlaceholderText("you@example.com")
        form.addRow("Email:", self._email_edit)

        self._alg_combo = QComboBox()
        self._alg_combo.addItems(["ed25519", "rsa4096", "cv25519"])
        form.addRow("Algorithm:", self._alg_combo)

        self._expiry_edit = QLineEdit("2y")
        self._expiry_edit.setPlaceholderText("e.g. 2y, 1y, 0 (no expiry)")
        form.addRow("Expiry:", self._expiry_edit)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Optional passphrase (leave empty for no passphrase)")
        form.addRow("Passphrase:", self._pass_edit)

        show_cb = QCheckBox("Show passphrase")
        show_cb.toggled.connect(lambda on: self._pass_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
        ))
        form.addRow("", show_cb)

        layout.addWidget(grp)

        note = QLabel(
            "Note: Key generation uses <code>gpg --batch --gen-key</code>. "
            "The key is added to your local GPG keyring. "
            "Use the Key Ring tab to export it."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        layout.addWidget(note)

        gen_btn = QPushButton("🔑  Generate Key")
        gen_btn.setStyleSheet("background:#1D4ED8;color:white;font-weight:bold;padding:8px 20px;")
        gen_btn.clicked.connect(self._on_generate)
        layout.addWidget(gen_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Output will appear here…")
        self._output.setStyleSheet("background:#0F172A;color:#A5F3FC;font-family:monospace;font-size:10px;")
        layout.addWidget(self._output, stretch=1)

    def _on_generate(self):
        name = self._name_edit.text().strip()
        email = self._email_edit.text().strip()
        if not name or not email:
            QMessageBox.warning(self, "Input Required", "Name and email are required.")
            return
        alg = self._alg_combo.currentText()
        expiry = self._expiry_edit.text().strip() or "2y"
        passphrase = self._pass_edit.text() or None

        self._output.setPlainText("Generating key… (this may take a moment)")
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["generate_key_batch"]).generate_key_batch(
                name=name, email=email, algorithm=alg,
                expiry=expiry, passphrase=passphrase
            ),
            callback=self._on_result,
        )

    def _on_result(self, r):
        if r.success:
            self._output.setPlainText(
                f"✓ Key generated successfully.\n\n"
                f"Command:\n{r.command_str}\n\n"
                f"Output:\n{r.stdout or r.stderr}"
            )
        else:
            self._output.setPlainText(
                f"✗ Key generation failed.\n\n"
                f"Command:\n{r.command_str}\n\n"
                f"Error:\n{r.stderr}"
            )


# ---------------------------------------------------------------------------
# Tab 2: Key Ring
# ---------------------------------------------------------------------------

class _KeyRingTab(QWidget):
    def __init__(self, panel: "GPGPanel", parent=None):
        super().__init__(parent)
        self._panel = panel
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # Toolbar
        toolbar = QHBoxLayout()
        list_pub_btn = QPushButton("List Public Keys")
        list_pub_btn.clicked.connect(lambda: self._list_keys(secret=False))
        list_sec_btn = QPushButton("List Secret Keys")
        list_sec_btn.clicked.connect(lambda: self._list_keys(secret=True))
        toolbar.addWidget(list_pub_btn)
        toolbar.addWidget(list_sec_btn)
        toolbar.addStretch()

        import_btn = QPushButton("📥  Import Key…")
        import_btn.clicked.connect(self._on_import)
        toolbar.addWidget(import_btn)

        layout.addLayout(toolbar)

        # Key list output
        self._key_list = QTextEdit()
        self._key_list.setReadOnly(True)
        self._key_list.setPlaceholderText("Key listing will appear here…")
        self._key_list.setStyleSheet("background:#0F172A;color:#A5F3FC;font-family:monospace;font-size:10px;")
        layout.addWidget(self._key_list, stretch=1)

        # Export section
        grp = QGroupBox("Export Key")
        exp_form = QFormLayout(grp)
        exp_form.setSpacing(8)

        self._export_id_edit = QLineEdit()
        self._export_id_edit.setPlaceholderText("Key ID or email address")
        exp_form.addRow("Key ID / Email:", self._export_id_edit)

        exp_row = QHBoxLayout()
        self._export_path_edit = QLineEdit()
        self._export_path_edit.setPlaceholderText("Output .asc file path…")
        self._export_path_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_export)
        exp_row.addWidget(self._export_path_edit, stretch=1)
        exp_row.addWidget(browse_btn)
        exp_form.addRow("Output file:", exp_row)

        export_btn = QPushButton("📤  Export Public Key")
        export_btn.setStyleSheet("background:#1D4ED8;color:white;font-weight:bold;")
        export_btn.clicked.connect(self._on_export)
        exp_form.addRow("", export_btn)

        layout.addWidget(grp)

    def _list_keys(self, secret: bool):
        self._key_list.setPlainText("Loading…")
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["list_keys"]).list_keys(secret=secret),
            callback=self._on_list_result,
        )

    def _on_list_result(self, r):
        if r.success:
            self._key_list.setPlainText(r.stdout or "(no keys found)")
        else:
            self._key_list.setPlainText(f"Error:\n{r.stderr}")

    def _browse_export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Key", "public_key.asc", "ASC Files (*.asc);;All Files (*)"
        )
        if path:
            self._export_path_edit.setText(path)

    def _on_import(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Key", "", "Key Files (*.asc *.gpg);;All Files (*)"
        )
        if not path:
            return
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["import_key"]).import_key(path),
            callback=lambda r: self._key_list.setPlainText(
                f"✓ Import successful.\n\n{r.stdout or r.stderr}" if r.success
                else f"✗ Import failed.\n\n{r.stderr}"
            ),
        )

    def _on_export(self):
        key_id = self._export_id_edit.text().strip()
        out_path = self._export_path_edit.text().strip()
        if not key_id:
            QMessageBox.warning(self, "Input Required", "Enter a key ID or email address.")
            return
        if not out_path:
            QMessageBox.warning(self, "Input Required", "Choose an output file path.")
            return
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["export_public_key"]).export_public_key(
                key_id, out_path
            ),
            callback=lambda r: QMessageBox.information(
                self, "Export",
                f"Key exported to {out_path}" if r.success else f"Export failed:\n{r.stderr}"
            ),
        )


# ---------------------------------------------------------------------------
# Tab 3: Encrypt / Decrypt
# ---------------------------------------------------------------------------

class _EncryptDecryptTab(QWidget):
    def __init__(self, panel: "GPGPanel", parent=None):
        super().__init__(parent)
        self._panel = panel
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Encrypt group
        enc_grp = QGroupBox("Encrypt File")
        enc_form = QFormLayout(enc_grp)
        enc_form.setSpacing(8)

        input_row = QHBoxLayout()
        self._enc_input = QLineEdit()
        self._enc_input.setPlaceholderText("File to encrypt…")
        self._enc_input.setReadOnly(True)
        enc_in_browse = QPushButton("Browse…")
        enc_in_browse.clicked.connect(lambda: self._browse(self._enc_input, open=True))
        input_row.addWidget(self._enc_input, stretch=1)
        input_row.addWidget(enc_in_browse)
        enc_form.addRow("Input file:", input_row)

        out_row = QHBoxLayout()
        self._enc_output = QLineEdit()
        self._enc_output.setPlaceholderText("Output .asc / .gpg file…")
        self._enc_output.setReadOnly(True)
        enc_out_browse = QPushButton("Browse…")
        enc_out_browse.clicked.connect(lambda: self._browse(self._enc_output, open=False))
        out_row.addWidget(self._enc_output, stretch=1)
        out_row.addWidget(enc_out_browse)
        enc_form.addRow("Output file:", out_row)

        self._recipients_edit = QLineEdit()
        self._recipients_edit.setPlaceholderText("Comma-separated key IDs or emails")
        enc_form.addRow("Recipients:", self._recipients_edit)

        self._sign_id_edit = QLineEdit()
        self._sign_id_edit.setPlaceholderText("Optional: sign with this key ID / email")
        enc_form.addRow("Sign with:", self._sign_id_edit)

        self._armor_cb = QCheckBox("ASCII-armored output (.asc)")
        self._armor_cb.setChecked(True)
        enc_form.addRow("", self._armor_cb)

        enc_btn = QPushButton("🔒  Encrypt")
        enc_btn.setStyleSheet("background:#1D4ED8;color:white;font-weight:bold;")
        enc_btn.clicked.connect(self._on_encrypt)
        enc_form.addRow("", enc_btn)

        layout.addWidget(enc_grp)

        # Decrypt group
        dec_grp = QGroupBox("Decrypt File")
        dec_form = QFormLayout(dec_grp)
        dec_form.setSpacing(8)

        dec_in_row = QHBoxLayout()
        self._dec_input = QLineEdit()
        self._dec_input.setPlaceholderText("Encrypted file (.gpg / .asc)…")
        self._dec_input.setReadOnly(True)
        dec_in_browse = QPushButton("Browse…")
        dec_in_browse.clicked.connect(lambda: self._browse(self._dec_input, open=True))
        dec_in_row.addWidget(self._dec_input, stretch=1)
        dec_in_row.addWidget(dec_in_browse)
        dec_form.addRow("Input file:", dec_in_row)

        dec_out_row = QHBoxLayout()
        self._dec_output = QLineEdit()
        self._dec_output.setPlaceholderText("Output decrypted file…")
        self._dec_output.setReadOnly(True)
        dec_out_browse = QPushButton("Browse…")
        dec_out_browse.clicked.connect(lambda: self._browse(self._dec_output, open=False))
        dec_out_row.addWidget(self._dec_output, stretch=1)
        dec_out_row.addWidget(dec_out_browse)
        dec_form.addRow("Output file:", dec_out_row)

        self._dec_pass_edit = QLineEdit()
        self._dec_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._dec_pass_edit.setPlaceholderText("Optional passphrase (if key is passphrase-protected)")
        dec_form.addRow("Passphrase:", self._dec_pass_edit)

        dec_btn = QPushButton("🔓  Decrypt")
        dec_btn.setStyleSheet("background:#065F46;color:white;font-weight:bold;")
        dec_btn.clicked.connect(self._on_decrypt)
        dec_form.addRow("", dec_btn)

        layout.addWidget(dec_grp)

        self._status = QLabel()
        self._status.setStyleSheet("font-size:11px;")
        layout.addWidget(self._status)
        layout.addStretch()

    def _browse(self, edit: QLineEdit, open: bool):
        if open:
            path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _on_encrypt(self):
        inp = self._enc_input.text().strip()
        out = self._enc_output.text().strip()
        rcpts_raw = self._recipients_edit.text().strip()
        if not inp or not out or not rcpts_raw:
            QMessageBox.warning(self, "Input Required", "Input file, output file, and recipients are required.")
            return
        recipients = [r.strip() for r in rcpts_raw.split(",") if r.strip()]
        sign_id = self._sign_id_edit.text().strip() or None
        armor = self._armor_cb.isChecked()

        self._status.setText("Encrypting…")
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["encrypt_file"]).encrypt_file(
                inp, out, recipients, sign_key_id=sign_id, armor=armor
            ),
            callback=self._on_enc_result,
        )

    def _on_enc_result(self, r):
        if r.success:
            self._status.setText(f"✓  File encrypted successfully.")
            self._status.setStyleSheet("font-size:11px;color:#34D399;")
        else:
            self._status.setText(f"✗  Encryption failed: {r.stderr[:120]}")
            self._status.setStyleSheet("font-size:11px;color:#F87171;")

    def _on_decrypt(self):
        inp = self._dec_input.text().strip()
        out = self._dec_output.text().strip()
        if not inp or not out:
            QMessageBox.warning(self, "Input Required", "Input and output file paths are required.")
            return
        passphrase = self._dec_pass_edit.text() or None

        self._status.setText("Decrypting…")
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["decrypt_file"]).decrypt_file(
                inp, out, passphrase=passphrase
            ),
            callback=self._on_dec_result,
        )

    def _on_dec_result(self, r):
        if r.success:
            self._status.setText("✓  File decrypted successfully.")
            self._status.setStyleSheet("font-size:11px;color:#34D399;")
        else:
            self._status.setText(f"✗  Decryption failed: {r.stderr[:120]}")
            self._status.setStyleSheet("font-size:11px;color:#F87171;")


# ---------------------------------------------------------------------------
# Tab 4: Sign / Verify
# ---------------------------------------------------------------------------

class _SignVerifyTab(QWidget):
    def __init__(self, panel: "GPGPanel", parent=None):
        super().__init__(parent)
        self._panel = panel
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Sign group
        sign_grp = QGroupBox("Sign File")
        sign_form = QFormLayout(sign_grp)
        sign_form.setSpacing(8)

        sign_in_row = QHBoxLayout()
        self._sign_input = QLineEdit()
        self._sign_input.setPlaceholderText("File to sign…")
        self._sign_input.setReadOnly(True)
        sign_in_browse = QPushButton("Browse…")
        sign_in_browse.clicked.connect(lambda: self._browse(self._sign_input, open=True))
        sign_in_row.addWidget(self._sign_input, stretch=1)
        sign_in_row.addWidget(sign_in_browse)
        sign_form.addRow("Input file:", sign_in_row)

        sign_out_row = QHBoxLayout()
        self._sign_output = QLineEdit()
        self._sign_output.setPlaceholderText("Signature output file (.sig / .asc)…")
        self._sign_output.setReadOnly(True)
        sign_out_browse = QPushButton("Browse…")
        sign_out_browse.clicked.connect(lambda: self._browse(self._sign_output, open=False))
        sign_out_row.addWidget(self._sign_output, stretch=1)
        sign_out_row.addWidget(sign_out_browse)
        sign_form.addRow("Signature file:", sign_out_row)

        self._sign_key_edit = QLineEdit()
        self._sign_key_edit.setPlaceholderText("Key ID or email to sign with")
        sign_form.addRow("Signing key:", self._sign_key_edit)

        opts_row = QHBoxLayout()
        self._detach_cb = QCheckBox("Detached signature")
        self._detach_cb.setChecked(True)
        self._armor_sign_cb = QCheckBox("ASCII-armored")
        self._armor_sign_cb.setChecked(True)
        opts_row.addWidget(self._detach_cb)
        opts_row.addWidget(self._armor_sign_cb)
        opts_row.addStretch()
        sign_form.addRow("Options:", opts_row)

        sign_btn = QPushButton("✍️  Sign File")
        sign_btn.setStyleSheet("background:#1D4ED8;color:white;font-weight:bold;")
        sign_btn.clicked.connect(self._on_sign)
        sign_form.addRow("", sign_btn)

        layout.addWidget(sign_grp)

        # Verify group
        verify_grp = QGroupBox("Verify Signature")
        verify_form = QFormLayout(verify_grp)
        verify_form.setSpacing(8)

        sig_row = QHBoxLayout()
        self._verify_sig = QLineEdit()
        self._verify_sig.setPlaceholderText("Signature file (.sig / .asc)…")
        self._verify_sig.setReadOnly(True)
        sig_browse = QPushButton("Browse…")
        sig_browse.clicked.connect(lambda: self._browse(self._verify_sig, open=True))
        sig_row.addWidget(self._verify_sig, stretch=1)
        sig_row.addWidget(sig_browse)
        verify_form.addRow("Signature file:", sig_row)

        orig_row = QHBoxLayout()
        self._verify_orig = QLineEdit()
        self._verify_orig.setPlaceholderText("Original file (for detached sig, optional for inline)…")
        self._verify_orig.setReadOnly(True)
        orig_browse = QPushButton("Browse…")
        orig_browse.clicked.connect(lambda: self._browse(self._verify_orig, open=True))
        orig_row.addWidget(self._verify_orig, stretch=1)
        orig_row.addWidget(orig_browse)
        verify_form.addRow("Original file:", orig_row)

        verify_btn = QPushButton("✅  Verify Signature")
        verify_btn.setStyleSheet("background:#065F46;color:white;font-weight:bold;")
        verify_btn.clicked.connect(self._on_verify)
        verify_form.addRow("", verify_btn)

        layout.addWidget(verify_grp)

        self._result_label = QLabel()
        self._result_label.setWordWrap(True)
        self._result_label.setStyleSheet("font-size:12px;padding:8px;border-radius:4px;")
        layout.addWidget(self._result_label)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Operation output will appear here…")
        self._output.setStyleSheet("background:#0F172A;color:#A5F3FC;font-family:monospace;font-size:10px;")
        layout.addWidget(self._output, stretch=1)

    def _browse(self, edit: QLineEdit, open: bool):
        if open:
            path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _on_sign(self):
        inp = self._sign_input.text().strip()
        out = self._sign_output.text().strip()
        key_id = self._sign_key_edit.text().strip()
        if not inp or not out or not key_id:
            QMessageBox.warning(self, "Input Required", "Input file, output file, and signing key are required.")
            return
        detached = self._detach_cb.isChecked()
        armor = self._armor_sign_cb.isChecked()

        self._output.setPlainText("Signing…")
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["sign_file"]).sign_file(
                inp, out, key_id, detached=detached, armor=armor
            ),
            callback=self._on_sign_result,
        )

    def _on_sign_result(self, r):
        if r.success:
            self._result_label.setText("✓  File signed successfully.")
            self._result_label.setStyleSheet(
                "font-size:12px;padding:8px;border-radius:4px;background:#064E3B;color:#34D399;"
            )
            self._output.setPlainText(f"Command:\n{r.command_str}\n\nOutput:\n{r.stdout or r.stderr}")
        else:
            self._result_label.setText("✗  Signing failed.")
            self._result_label.setStyleSheet(
                "font-size:12px;padding:8px;border-radius:4px;background:#450A0A;color:#F87171;"
            )
            self._output.setPlainText(f"Command:\n{r.command_str}\n\nError:\n{r.stderr}")

    def _on_verify(self):
        sig = self._verify_sig.text().strip()
        orig = self._verify_orig.text().strip() or None
        if not sig:
            QMessageBox.warning(self, "Input Required", "Signature file is required.")
            return

        self._output.setPlainText("Verifying…")
        self._panel.run_in_thread(
            lambda: __import__("modules.gpg.controller", fromlist=["verify_file"]).verify_file(
                sig, file_path=orig
            ),
            callback=self._on_verify_result,
        )

    def _on_verify_result(self, r):
        if r.success:
            self._result_label.setText("✓  VALID — Signature verified successfully.")
            self._result_label.setStyleSheet(
                "font-size:12px;padding:8px;border-radius:4px;background:#064E3B;color:#34D399;"
            )
        else:
            self._result_label.setText("✗  INVALID — Signature verification failed.")
            self._result_label.setStyleSheet(
                "font-size:12px;padding:8px;border-radius:4px;background:#450A0A;color:#F87171;"
            )
        self._output.setPlainText(f"Command:\n{r.command_str}\n\n{r.stdout or ''}{r.stderr or ''}")


# ---------------------------------------------------------------------------
# GPGPanel (BasePanel subclass)
# ---------------------------------------------------------------------------

class GPGPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Title row
        title_row = QHBoxLayout()
        title = QLabel("🔐  GnuPG / OpenPGP Integration")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        title_row.addWidget(title)
        title_row.addStretch()
        ver_lbl = QLabel("gpg2 required (≥ 2.2)")
        ver_lbl.setStyleSheet("color: #4B5563; font-size: 10px;")
        title_row.addWidget(ver_lbl)
        layout.addLayout(title_row)

        tabs = QTabWidget()
        tabs.addTab(_GenerateKeyTab(self), "🔑 Generate Key")
        tabs.addTab(_KeyRingTab(self), "🗝 Key Ring")
        tabs.addTab(_EncryptDecryptTab(self), "🔒 Encrypt / Decrypt")
        tabs.addTab(_SignVerifyTab(self), "✍️ Sign / Verify")
        layout.addWidget(tabs, stretch=1)
