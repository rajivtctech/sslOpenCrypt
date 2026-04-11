"""
ui/panels/smime_panel.py — Module 6: S/MIME & Email panel.
"""

from PyQt6.QtWidgets import (
    QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget,
    QVBoxLayout, QWidget,
)

from modules.smime.controller import encrypt_message, decrypt_message, sign_message, verify_message
from .base_panel import BasePanel


class SMIMEPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("📧  S/MIME & Email Encryption")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        desc = QLabel(
            "Encrypt, decrypt, sign, and verify S/MIME email messages.\n"
            "Export PKCS#12 bundles for import into Thunderbird, Outlook, or Apple Mail."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(desc)

        tabs = QTabWidget()
        tabs.addTab(self._build_encrypt_tab(), "Encrypt")
        tabs.addTab(self._build_decrypt_tab(), "Decrypt")
        tabs.addTab(self._build_sign_tab(), "Sign")
        tabs.addTab(self._build_verify_tab(), "Verify")
        layout.addWidget(tabs, stretch=1)

    def _browse(self, edit, save=False):
        if save:
            path, _ = QFileDialog.getSaveFileName(self, "Save", "", "All Files (*)")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _build_encrypt_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        form = QFormLayout()

        self._enc_msg = QLineEdit(); self._enc_msg.setPlaceholderText("Message file (text or MIME)")
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._enc_msg))
        r1 = QHBoxLayout(); r1.addWidget(self._enc_msg); r1.addWidget(b1)
        form.addRow("Message:", r1)

        self._enc_cert = QLineEdit(); self._enc_cert.setPlaceholderText("Recipient certificate .pem")
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._enc_cert))
        r2 = QHBoxLayout(); r2.addWidget(self._enc_cert); r2.addWidget(b2)
        form.addRow("Recipient Cert:", r2)

        self._enc_out = QLineEdit(); self._enc_out.setPlaceholderText("encrypted_message.pem")
        b3 = QPushButton("Browse…"); b3.setMaximumWidth(80); b3.clicked.connect(lambda: self._browse(self._enc_out, save=True))
        r3 = QHBoxLayout(); r3.addWidget(self._enc_out); r3.addWidget(b3)
        form.addRow("Output:", r3)
        l.addLayout(form)

        btn = QPushButton("Encrypt Message")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_encrypt)
        l.addWidget(btn)

        self._enc_status = self.build_status_label()
        l.addWidget(self._enc_status)
        _, self._enc_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_encrypt(self):
        msg = self._enc_msg.text().strip(); cert = self._enc_cert.text().strip()
        out = self._enc_out.text().strip()
        if not all([msg, cert, out]):
            return
        self.run_in_thread(encrypt_message, msg, cert, out, callback=self._on_enc_done)

    def _on_enc_done(self, r):
        self.show_result(r, self._enc_output, self._enc_status)

    def _build_decrypt_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        form = QFormLayout()

        self._dec_msg = QLineEdit()
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._dec_msg))
        r1 = QHBoxLayout(); r1.addWidget(self._dec_msg); r1.addWidget(b1)
        form.addRow("Encrypted message:", r1)

        self._dec_key = QLineEdit()
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._dec_key))
        r2 = QHBoxLayout(); r2.addWidget(self._dec_key); r2.addWidget(b2)
        form.addRow("Private key:", r2)

        self._dec_cert = QLineEdit()
        b3 = QPushButton("Browse…"); b3.setMaximumWidth(80); b3.clicked.connect(lambda: self._browse(self._dec_cert))
        r3 = QHBoxLayout(); r3.addWidget(self._dec_cert); r3.addWidget(b3)
        form.addRow("Certificate:", r3)

        self._dec_out = QLineEdit(); self._dec_out.setPlaceholderText("decrypted.txt")
        b4 = QPushButton("Browse…"); b4.setMaximumWidth(80); b4.clicked.connect(lambda: self._browse(self._dec_out, save=True))
        r4 = QHBoxLayout(); r4.addWidget(self._dec_out); r4.addWidget(b4)
        form.addRow("Output:", r4)

        self._dec_pass = QLineEdit(); self._dec_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Key Passphrase:", self._dec_pass)
        l.addLayout(form)

        btn = QPushButton("Decrypt Message")
        btn.setStyleSheet("background:#065F46; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_decrypt)
        l.addWidget(btn)

        self._dec_status = self.build_status_label()
        l.addWidget(self._dec_status)
        _, self._dec_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_decrypt(self):
        msg = self._dec_msg.text().strip(); key = self._dec_key.text().strip()
        cert = self._dec_cert.text().strip(); out = self._dec_out.text().strip()
        if not all([msg, key, cert, out]):
            return
        passphrase = self._dec_pass.text() or None
        self.run_in_thread(decrypt_message, msg, key, cert, out, passphrase, callback=self._on_dec_done)

    def _on_dec_done(self, r):
        self.show_result(r, self._dec_output, self._dec_status)

    def _build_sign_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        form = QFormLayout()

        self._sgn_msg = QLineEdit()
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._sgn_msg))
        r1 = QHBoxLayout(); r1.addWidget(self._sgn_msg); r1.addWidget(b1)
        form.addRow("Message:", r1)

        self._sgn_key = QLineEdit()
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._sgn_key))
        r2 = QHBoxLayout(); r2.addWidget(self._sgn_key); r2.addWidget(b2)
        form.addRow("Private Key:", r2)

        self._sgn_cert = QLineEdit()
        b3 = QPushButton("Browse…"); b3.setMaximumWidth(80); b3.clicked.connect(lambda: self._browse(self._sgn_cert))
        r3 = QHBoxLayout(); r3.addWidget(self._sgn_cert); r3.addWidget(b3)
        form.addRow("Certificate:", r3)

        self._sgn_out = QLineEdit()
        b4 = QPushButton("Browse…"); b4.setMaximumWidth(80); b4.clicked.connect(lambda: self._browse(self._sgn_out, save=True))
        r4 = QHBoxLayout(); r4.addWidget(self._sgn_out); r4.addWidget(b4)
        form.addRow("Signed Output:", r4)

        self._sgn_pass = QLineEdit(); self._sgn_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Key Passphrase:", self._sgn_pass)
        l.addLayout(form)

        btn = QPushButton("Sign Message")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_sign)
        l.addWidget(btn)

        self._sgn_status = self.build_status_label()
        l.addWidget(self._sgn_status)
        _, self._sgn_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_sign(self):
        msg = self._sgn_msg.text().strip(); key = self._sgn_key.text().strip()
        cert = self._sgn_cert.text().strip(); out = self._sgn_out.text().strip()
        if not all([msg, key, cert, out]):
            return
        passphrase = self._sgn_pass.text() or None
        self.run_in_thread(sign_message, msg, key, cert, out, passphrase, callback=self._on_sgn_done)

    def _on_sgn_done(self, r):
        self.show_result(r, self._sgn_output, self._sgn_status)

    def _build_verify_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        form = QFormLayout()

        self._ver_msg = QLineEdit()
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._ver_msg))
        r1 = QHBoxLayout(); r1.addWidget(self._ver_msg); r1.addWidget(b1)
        form.addRow("Signed message:", r1)

        self._ver_ca = QLineEdit(); self._ver_ca.setPlaceholderText("CA bundle (optional)")
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._ver_ca))
        r2 = QHBoxLayout(); r2.addWidget(self._ver_ca); r2.addWidget(b2)
        form.addRow("CA Bundle:", r2)
        l.addLayout(form)

        btn = QPushButton("Verify Signed Message")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_verify)
        l.addWidget(btn)

        self._ver_status = self.build_status_label()
        l.addWidget(self._ver_status)
        _, self._ver_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_verify(self):
        msg = self._ver_msg.text().strip(); ca = self._ver_ca.text().strip() or None
        if not msg:
            return
        self.run_in_thread(verify_message, msg, ca, callback=self._on_ver_done)

    def _on_ver_done(self, r):
        self.show_result(r, self._ver_output, self._ver_status)
