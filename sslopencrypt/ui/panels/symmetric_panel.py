"""
ui/panels/symmetric_panel.py — Module 2: Symmetric Encryption panel.
"""

from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from modules.symmetric.controller import (
    ALL_CIPHERS, BEGINNER_CIPHERS, _DEPRECATED,
    encrypt_file, decrypt_file, encrypt_text, decrypt_text,
)
from modules.symmetric.ghost_crypt import (
    SUPPORTED_CIPHERS as GHOST_CIPHERS,
    create_container, open_container,
    create_deniable_container, open_deniable_container,
)
from .base_panel import BasePanel

_GHOST_TAB_INDEX = 2  # index of the Ghost Crypt tab in QTabWidget


class SymmetricPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._expert = False
        self._deprecated_widget = None
        self._deprecated_cb = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🔒  Symmetric Encryption & Decryption")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        desc = QLabel(
            "Encrypt and decrypt files or text using symmetric ciphers.\n"
            "AES-256-GCM is the recommended default (AEAD — authenticated encryption)."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(desc)

        self._tabs = QTabWidget()
        self._tabs.addTab(self._build_file_tab(), "File")
        self._tabs.addTab(self._build_text_tab(), "Text")
        self._tabs.addTab(self._build_ghost_crypt_tab(), "Ghost Crypt")
        # Ghost Crypt tab hidden in Beginner Mode
        self._tabs.setTabVisible(_GHOST_TAB_INDEX, False)
        layout.addWidget(self._tabs, stretch=1)

    def _build_file_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._sf_in = QLineEdit()
        self._sf_in.setPlaceholderText("Input file path")
        btn_in = QPushButton("Browse…")
        btn_in.setMaximumWidth(80)
        btn_in.clicked.connect(lambda: self._browse(self._sf_in))
        row_in = QHBoxLayout()
        row_in.addWidget(self._sf_in)
        row_in.addWidget(btn_in)
        form.addRow("Input:", row_in)

        self._sf_out = QLineEdit()
        self._sf_out.setPlaceholderText("Output file path")
        btn_out = QPushButton("Browse…")
        btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse_save(self._sf_out))
        row_out = QHBoxLayout()
        row_out.addWidget(self._sf_out)
        row_out.addWidget(btn_out)
        form.addRow("Output:", row_out)

        self._sf_cipher = QComboBox()
        self._sf_cipher.addItems(BEGINNER_CIPHERS)
        self._sf_cipher.currentTextChanged.connect(self._on_cipher_changed_file)
        form.addRow("Cipher:", self._sf_cipher)

        self._sf_pass = QLineEdit()
        self._sf_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._sf_pass.setPlaceholderText("Passphrase")
        form.addRow("Passphrase:", self._sf_pass)
        l.addLayout(form)

        # Deprecated warning placeholder
        self._sf_deprecated_area = QVBoxLayout()
        l.addLayout(self._sf_deprecated_area)

        # Encrypt/Decrypt buttons
        btns = QHBoxLayout()
        self._sf_btn_enc = QPushButton("Encrypt")
        self._sf_btn_enc.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        self._sf_btn_enc.clicked.connect(self._do_encrypt_file)
        self._sf_btn_dec = QPushButton("Decrypt")
        self._sf_btn_dec.setStyleSheet("background:#065F46; color:white; padding:8px; border-radius:6px;")
        self._sf_btn_dec.clicked.connect(self._do_decrypt_file)
        btns.addWidget(self._sf_btn_enc)
        btns.addWidget(self._sf_btn_dec)
        l.addLayout(btns)

        # CBC warning
        self._cbc_warn = QLabel()
        self._cbc_warn.setWordWrap(True)
        self._cbc_warn.setStyleSheet("color: #FCD34D; font-size: 10px; font-style: italic;")
        self._cbc_warn.setVisible(False)
        l.addWidget(self._cbc_warn)

        self._sf_status = self.build_status_label()
        l.addWidget(self._sf_status)
        _, self._sf_out_text = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _browse(self, edit):
        path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _browse_save(self, edit):
        path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _on_cipher_changed_file(self, cipher: str):
        show_cbc_warn = cipher.endswith("-CBC")
        self._cbc_warn.setVisible(show_cbc_warn)
        if show_cbc_warn:
            self._cbc_warn.setText(
                "⚠  CBC mode does not provide authentication (integrity). "
                "Consider AES-256-GCM for authenticated encryption."
            )
        # Clear deprecated widget
        for i in reversed(range(self._sf_deprecated_area.count())):
            widget = self._sf_deprecated_area.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        if cipher in _DEPRECATED and self._expert:
            widget, cb = self.build_deprecated_warning_widget(cipher)
            self._sf_deprecated_area.addWidget(widget)
            self._deprecated_cb = cb
            cb.stateChanged.connect(lambda s: self._sf_btn_enc.setEnabled(bool(s)))
            self._sf_btn_enc.setEnabled(False)

    def _do_encrypt_file(self):
        inp = self._sf_in.text().strip()
        out = self._sf_out.text().strip()
        cipher = self._sf_cipher.currentText()
        passphrase = self._sf_pass.text()
        if not inp or not out or not passphrase:
            self._sf_status.setText("✗  Please fill in all fields")
            self._sf_status.setStyleSheet("color: #F87171;")
            return
        self.run_in_thread(encrypt_file, inp, out, cipher, passphrase, callback=self._on_file_done)

    def _do_decrypt_file(self):
        inp = self._sf_in.text().strip()
        out = self._sf_out.text().strip()
        cipher = self._sf_cipher.currentText()
        passphrase = self._sf_pass.text()
        if not inp or not out or not passphrase:
            return
        self.run_in_thread(decrypt_file, inp, out, cipher, passphrase, callback=self._on_file_done)

    def _on_file_done(self, r):
        self.show_result(r, self._sf_out_text, self._sf_status)
        if r.success:
            self._sf_status.setText("✓  Done")
            self._sf_status.setStyleSheet("color: #34D399; font-weight: bold;")

    def _build_text_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._st_text = QTextEdit()
        self._st_text.setPlaceholderText("Enter plaintext to encrypt, or ciphertext (Base64) to decrypt…")
        self._st_text.setMaximumHeight(100)
        form.addRow("Text:", self._st_text)

        self._st_cipher = QComboBox()
        self._st_cipher.addItems(BEGINNER_CIPHERS)
        form.addRow("Cipher:", self._st_cipher)

        self._st_pass = QLineEdit()
        self._st_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._st_pass.setPlaceholderText("Passphrase")
        form.addRow("Passphrase:", self._st_pass)
        l.addLayout(form)

        btns = QHBoxLayout()
        btn_enc = QPushButton("Encrypt → Base64")
        btn_enc.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn_enc.clicked.connect(self._do_encrypt_text)
        btn_dec = QPushButton("Decrypt ← Base64")
        btn_dec.setStyleSheet("background:#065F46; color:white; padding:8px; border-radius:6px;")
        btn_dec.clicked.connect(self._do_decrypt_text)
        btns.addWidget(btn_enc)
        btns.addWidget(btn_dec)
        l.addLayout(btns)

        self._st_status = self.build_status_label()
        l.addWidget(self._st_status)
        _, self._st_out = self.build_output_area("Result")
        l.addWidget(_, stretch=1)
        return w

    def _do_encrypt_text(self):
        text = self._st_text.toPlainText()
        cipher = self._st_cipher.currentText()
        passphrase = self._st_pass.text()
        if not text or not passphrase:
            return
        self.run_in_thread(encrypt_text, text, cipher, passphrase, callback=self._on_text_done)

    def _do_decrypt_text(self):
        text = self._st_text.toPlainText().strip()
        cipher = self._st_cipher.currentText()
        passphrase = self._st_pass.text()
        if not text or not passphrase:
            return
        self.run_in_thread(decrypt_text, text, cipher, passphrase, callback=self._on_text_done)

    def _on_text_done(self, r):
        self.show_result(r, self._st_out, self._st_status)

    # ------------------------------------------------------------------
    # Ghost Crypt tab (Expert Mode only) — inner sub-tabs: v1.1 Standard | v1.2 Deniable
    # ------------------------------------------------------------------

    def _build_ghost_crypt_tab(self) -> QWidget:
        """
        Ghost Crypt outer tab: holds two inner sub-tabs.
          v1.1 Standard  — single-layer headerless container
          v1.2 Deniable  — dual-layer container with plausible deniability under coercion
        Shown only in Expert Mode.
        """
        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(0, 6, 0, 0)
        outer.setSpacing(0)

        inner_tabs = QTabWidget()
        inner_tabs.setStyleSheet("QTabBar::tab { padding: 5px 14px; }")
        inner_tabs.addTab(self._build_gc_standard_tab(), "v1.1 — Standard")
        inner_tabs.addTab(self._build_gc_deniable_tab(), "v1.2 — Deniable")
        outer.addWidget(inner_tabs)
        return w

    # ---- v1.1 Standard sub-tab ----

    def _build_gc_standard_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)
        l.setContentsMargins(10, 10, 10, 10)

        info = QLabel(
            "Ghost Crypt v1.1 creates a single-layer container indistinguishable from random noise.\n"
            "No magic bytes, no header, no length field — only the passphrase reveals its content.\n"
            "Key derivation: Argon2id (t=3, m=64 MiB, p=4).  Cipher: AES-256-GCM or ChaCha20-Poly1305."
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            "background:#1E3A5F; border:1px solid #3B82F6; border-radius:6px; "
            "color:#BFDBFE; font-size:10px; padding:8px;"
        )
        l.addWidget(info)

        form = QFormLayout()
        form.setSpacing(8)

        self._gc_in = QLineEdit()
        self._gc_in.setPlaceholderText("Plaintext file (Create) or Ghost Crypt container (Open)")
        btn_in = QPushButton("Browse…")
        btn_in.setMaximumWidth(80)
        btn_in.clicked.connect(lambda: self._browse(self._gc_in))
        row_in = QHBoxLayout()
        row_in.addWidget(self._gc_in)
        row_in.addWidget(btn_in)
        form.addRow("Input file:", row_in)

        self._gc_out = QLineEdit()
        self._gc_out.setPlaceholderText("Output file path")
        btn_out = QPushButton("Browse…")
        btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse_save(self._gc_out))
        row_out = QHBoxLayout()
        row_out.addWidget(self._gc_out)
        row_out.addWidget(btn_out)
        form.addRow("Output file:", row_out)

        self._gc_cipher = QComboBox()
        self._gc_cipher.addItems(GHOST_CIPHERS)
        form.addRow("Cipher:", self._gc_cipher)

        self._gc_pass = QLineEdit()
        self._gc_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._gc_pass.setPlaceholderText("Passphrase (Argon2id KDF — slow by design)")
        form.addRow("Passphrase:", self._gc_pass)

        l.addLayout(form)

        btns = QHBoxLayout()
        self._gc_btn_create = QPushButton("Create Container")
        self._gc_btn_create.setStyleSheet(
            "background:#1D4ED8; color:white; padding:8px; border-radius:6px; font-weight:bold;"
        )
        self._gc_btn_create.setToolTip("Encrypt the input file into a headerless Ghost Crypt container")
        self._gc_btn_create.clicked.connect(self._do_gc_create)

        self._gc_btn_open = QPushButton("Open Container")
        self._gc_btn_open.setStyleSheet(
            "background:#065F46; color:white; padding:8px; border-radius:6px; font-weight:bold;"
        )
        self._gc_btn_open.setToolTip("Decrypt an existing Ghost Crypt container to a plaintext file")
        self._gc_btn_open.clicked.connect(self._do_gc_open)

        btns.addWidget(self._gc_btn_create)
        btns.addWidget(self._gc_btn_open)
        l.addLayout(btns)

        self._gc_status = self.build_status_label()
        l.addWidget(self._gc_status)

        _, self._gc_out_text = self.build_output_area("Result")
        l.addWidget(_, stretch=1)
        return w

    # ---- v1.2 Deniable sub-tab ----

    def _build_gc_deniable_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(10)
        l.setContentsMargins(10, 10, 10, 10)

        info = QLabel(
            "Ghost Crypt v1.2 — dual-layer deniable container.\n"
            "Holds two independently encrypted payloads: real content and decoy content.\n"
            "Under coercion, reveal only the DECOY passphrase — the real payload cannot be proven to exist.\n"
            "Layout: segment 0 (real) ‖ segment 1 (decoy).  Opener tries both; returns whichever matches."
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            "background:#3B1F14; border:1px solid #F97316; border-radius:6px; "
            "color:#FED7AA; font-size:10px; padding:8px;"
        )
        l.addWidget(info)

        form = QFormLayout()
        form.setSpacing(8)

        # Real content (create only)
        self._gcd_real = QLineEdit()
        self._gcd_real.setPlaceholderText("Real content file (used when creating)")
        btn_real = QPushButton("Browse…")
        btn_real.setMaximumWidth(80)
        btn_real.clicked.connect(lambda: self._browse(self._gcd_real))
        row_real = QHBoxLayout()
        row_real.addWidget(self._gcd_real)
        row_real.addWidget(btn_real)
        form.addRow("Real content:", row_real)

        # Decoy content (create only)
        self._gcd_decoy = QLineEdit()
        self._gcd_decoy.setPlaceholderText("Decoy content file (used when creating)")
        btn_decoy = QPushButton("Browse…")
        btn_decoy.setMaximumWidth(80)
        btn_decoy.clicked.connect(lambda: self._browse(self._gcd_decoy))
        row_decoy = QHBoxLayout()
        row_decoy.addWidget(self._gcd_decoy)
        row_decoy.addWidget(btn_decoy)
        form.addRow("Decoy content:", row_decoy)

        # Container path
        self._gcd_container = QLineEdit()
        self._gcd_container.setPlaceholderText("Container file (.ghost)")
        btn_cont = QPushButton("Browse…")
        btn_cont.setMaximumWidth(80)
        btn_cont.clicked.connect(lambda: self._browse_save(self._gcd_container))
        row_cont = QHBoxLayout()
        row_cont.addWidget(self._gcd_container)
        row_cont.addWidget(btn_cont)
        form.addRow("Container:", row_cont)

        # Output (open only)
        self._gcd_out = QLineEdit()
        self._gcd_out.setPlaceholderText("Output file (used when opening)")
        btn_out = QPushButton("Browse…")
        btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse_save(self._gcd_out))
        row_out = QHBoxLayout()
        row_out.addWidget(self._gcd_out)
        row_out.addWidget(btn_out)
        form.addRow("Output file:", row_out)

        self._gcd_cipher = QComboBox()
        self._gcd_cipher.addItems(GHOST_CIPHERS)
        form.addRow("Cipher:", self._gcd_cipher)

        self._gcd_real_pass = QLineEdit()
        self._gcd_real_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._gcd_real_pass.setPlaceholderText("Real passphrase (guards the real content)")
        form.addRow("Real passphrase:", self._gcd_real_pass)

        self._gcd_decoy_pass = QLineEdit()
        self._gcd_decoy_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._gcd_decoy_pass.setPlaceholderText("Decoy passphrase (reveal this under coercion)")
        form.addRow("Decoy passphrase:", self._gcd_decoy_pass)

        open_note = QLabel("To open: fill Container + Output + one passphrase (real or decoy) — the tool finds the matching segment.")
        open_note.setWordWrap(True)
        open_note.setStyleSheet("color:#9CA3AF; font-size:10px;")
        form.addRow("", open_note)

        l.addLayout(form)

        btns = QHBoxLayout()
        self._gcd_btn_create = QPushButton("Create Deniable Container")
        self._gcd_btn_create.setStyleSheet(
            "background:#92400E; color:white; padding:8px; border-radius:6px; font-weight:bold;"
        )
        self._gcd_btn_create.setToolTip(
            "Create a dual-layer deniable container from real + decoy files"
        )
        self._gcd_btn_create.clicked.connect(self._do_gcd_create)

        self._gcd_btn_open = QPushButton("Open Deniable Container")
        self._gcd_btn_open.setStyleSheet(
            "background:#065F46; color:white; padding:8px; border-radius:6px; font-weight:bold;"
        )
        self._gcd_btn_open.setToolTip(
            "Decrypt — provide real OR decoy passphrase; tool auto-detects the matching segment"
        )
        self._gcd_btn_open.clicked.connect(self._do_gcd_open)

        btns.addWidget(self._gcd_btn_create)
        btns.addWidget(self._gcd_btn_open)
        l.addLayout(btns)

        self._gcd_status = self.build_status_label()
        l.addWidget(self._gcd_status)

        _, self._gcd_out_text = self.build_output_area("Result")
        l.addWidget(_, stretch=1)
        return w

    def _do_gc_create(self):
        inp = self._gc_in.text().strip()
        out = self._gc_out.text().strip()
        cipher = self._gc_cipher.currentText()
        passphrase = self._gc_pass.text()
        if not inp or not out or not passphrase:
            self._gc_status.setText("✗  Please fill in all fields")
            self._gc_status.setStyleSheet("color: #F87171;")
            return
        self._gc_btn_create.setEnabled(False)
        self._gc_status.setText("Creating container (Argon2id KDF — this takes a moment)…")
        self._gc_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(
            create_container, inp, out, passphrase, cipher,
            callback=self._on_gc_done,
        )

    def _do_gc_open(self):
        inp = self._gc_in.text().strip()
        out = self._gc_out.text().strip()
        cipher = self._gc_cipher.currentText()
        passphrase = self._gc_pass.text()
        if not inp or not out or not passphrase:
            self._gc_status.setText("✗  Please fill in all fields")
            self._gc_status.setStyleSheet("color: #F87171;")
            return
        self._gc_btn_open.setEnabled(False)
        self._gc_status.setText("Opening container (Argon2id KDF — this takes a moment)…")
        self._gc_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(
            open_container, inp, out, passphrase, cipher,
            callback=self._on_gc_done,
        )

    def _on_gc_done(self, r):
        self._gc_btn_create.setEnabled(True)
        self._gc_btn_open.setEnabled(True)
        self.show_result(r, self._gc_out_text, self._gc_status)
        if r.success:
            details = []
            if "plaintext_size" in r.parsed:
                details.append(f"Plaintext: {r.parsed['plaintext_size']} bytes")
            if "container_size" in r.parsed:
                details.append(f"Container: {r.parsed['container_size']} bytes")
            if details:
                self._gc_out_text.append("\n" + "  ".join(details))

    def _do_gcd_create(self):
        real = self._gcd_real.text().strip()
        decoy = self._gcd_decoy.text().strip()
        container = self._gcd_container.text().strip()
        cipher = self._gcd_cipher.currentText()
        real_pass = self._gcd_real_pass.text()
        decoy_pass = self._gcd_decoy_pass.text()
        if not real or not decoy or not container or not real_pass or not decoy_pass:
            self._gcd_status.setText("✗  Fill in real content, decoy content, container path, and both passphrases")
            self._gcd_status.setStyleSheet("color: #F87171;")
            return
        self._gcd_btn_create.setEnabled(False)
        self._gcd_status.setText("Creating deniable container (2 × Argon2id KDF — takes a moment)…")
        self._gcd_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(
            create_deniable_container, real, decoy, container, real_pass, decoy_pass, cipher,
            callback=self._on_gcd_done,
        )

    def _do_gcd_open(self):
        container = self._gcd_container.text().strip()
        out = self._gcd_out.text().strip()
        cipher = self._gcd_cipher.currentText()
        # Accept either passphrase field (whichever is filled); real takes priority
        passphrase = self._gcd_real_pass.text() or self._gcd_decoy_pass.text()
        if not container or not out or not passphrase:
            self._gcd_status.setText("✗  Fill in container, output, and at least one passphrase")
            self._gcd_status.setStyleSheet("color: #F87171;")
            return
        self._gcd_btn_open.setEnabled(False)
        self._gcd_status.setText("Opening deniable container (trying both segments)…")
        self._gcd_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(
            open_deniable_container, container, out, passphrase, cipher,
            callback=self._on_gcd_done,
        )

    def _on_gcd_done(self, r):
        self._gcd_btn_create.setEnabled(True)
        self._gcd_btn_open.setEnabled(True)
        self.show_result(r, self._gcd_out_text, self._gcd_status)
        if r.success:
            details = []
            if "real_size" in r.parsed:
                details.append(f"Real: {r.parsed['real_size']} B  Decoy: {r.parsed['decoy_size']} B")
            if "plaintext_size" in r.parsed:
                details.append(f"Decrypted: {r.parsed['plaintext_size']} bytes")
            if "container_size" in r.parsed:
                details.append(f"Container: {r.parsed['container_size']} bytes (2 × {r.parsed.get('segment_size', '?')} B segments)")
            if details:
                self._gcd_out_text.append("\n" + "\n".join(details))

    # ------------------------------------------------------------------

    def set_expert_mode(self, expert: bool):
        self._expert = expert
        for combo in [self._sf_cipher, self._st_cipher]:
            combo.clear()
            combo.addItems(ALL_CIPHERS if expert else BEGINNER_CIPHERS)
        # Show / hide the Ghost Crypt tab
        self._tabs.setTabVisible(_GHOST_TAB_INDEX, expert)
