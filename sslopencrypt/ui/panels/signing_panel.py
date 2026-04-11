"""
ui/panels/signing_panel.py — Module 5: Document & File Signing panel.
"""

import os
import tempfile

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMessageBox, QPushButton, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget,
)

from modules.signing.controller import (
    sign_file, verify_file, sign_raw, verify_raw, verify_bin_signed, PUBLIC_TSA_URLS,
)
from .base_panel import BasePanel


class SigningPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("✍️  Document & File Signing")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_sign_tab(), "Sign (CMS/PKCS#7)")
        tabs.addTab(self._build_verify_tab(), "Verify Signature")
        tabs.addTab(self._build_raw_tab(), "Raw Sign/Verify")
        tabs.addTab(self._build_pico_tab(), "RP2350 Firmware")
        layout.addWidget(tabs, stretch=1)

    def _use_vault_key(self, target_edit: QLineEdit):
        """
        Show vault key picker. Exports the selected key to a secure temp file,
        sets the path in target_edit, and schedules cleanup on close.
        """
        from modules.vault import controller as vc
        if not vc.is_unlocked():
            QMessageBox.information(
                self, "Vault Locked",
                "The Key Vault is locked.\n\nGo to the Key Vault panel and unlock it first."
            )
            return
        entries = vc.list_keys()
        if not entries:
            QMessageBox.information(self, "Vault Empty", "No keys in the vault.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Select Key from Vault")
        dlg.setMinimumWidth(400)
        dlg.setModal(True)
        layout = QVBoxLayout(dlg)
        layout.addWidget(QLabel("Select a private key from the vault:"))

        lst = QListWidget()
        for e in entries:
            tags = ", ".join(e.get("tags", []))
            text = f"{e['name']}  ({e['algorithm']})"
            if tags:
                text += f"  [{tags}]"
            item = QListWidgetItem(text)
            item.setData(Qt.ItemDataRole.UserRole, e["id"])
            lst.addItem(item)
        lst.setCurrentRow(0)
        layout.addWidget(lst)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        layout.addWidget(btn_box)

        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        sel = lst.currentItem()
        if not sel:
            return
        entry_id = sel.data(Qt.ItemDataRole.UserRole)

        # Export to a temp file (caller must not delete it — we track for cleanup)
        try:
            fd, tmp_path = tempfile.mkstemp(suffix=".pem", prefix="sslopencrypt_vault_")
            os.close(fd)
            vc.export_key_to_file(entry_id, tmp_path)
            target_edit.setText(tmp_path)
            target_edit.setToolTip(f"Vault key (temp file — will be cleaned up on exit)")
            if not hasattr(self, "_vault_tmp_files"):
                self._vault_tmp_files = []
            self._vault_tmp_files.append(tmp_path)
        except Exception as e:
            QMessageBox.critical(self, "Vault Error", f"Failed to export key: {e}")

    def _cleanup_vault_tmp_files(self):
        for path in getattr(self, "_vault_tmp_files", []):
            try:
                os.remove(path)
            except OSError:
                pass
        self._vault_tmp_files = []

    def closeEvent(self, event):
        self._cleanup_vault_tmp_files()
        super().closeEvent(event)

    def _browse(self, edit, save=False):
        if save:
            path, _ = QFileDialog.getSaveFileName(self, "Save", "", "All Files (*)")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open", "", "All Files (*)")
        if path:
            edit.setText(path)

    # ------------------------------------------------------------------
    def _build_sign_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        form = QFormLayout()

        self._s_file = QLineEdit(); self._s_file.setPlaceholderText("File to sign")
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._s_file))
        r1 = QHBoxLayout(); r1.addWidget(self._s_file); r1.addWidget(b1)
        form.addRow("File:", r1)

        self._s_key = QLineEdit(); self._s_key.setPlaceholderText("Private key .pem")
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._s_key))
        vault_btn2 = QPushButton("🔒 Vault"); vault_btn2.setMaximumWidth(64)
        vault_btn2.setToolTip("Use a key from the encrypted Key Vault")
        vault_btn2.clicked.connect(lambda: self._use_vault_key(self._s_key))
        r2 = QHBoxLayout(); r2.addWidget(self._s_key); r2.addWidget(b2); r2.addWidget(vault_btn2)
        form.addRow("Private Key:", r2)

        self._s_cert = QLineEdit(); self._s_cert.setPlaceholderText("Signing certificate .pem")
        b3 = QPushButton("Browse…"); b3.setMaximumWidth(80); b3.clicked.connect(lambda: self._browse(self._s_cert))
        r3 = QHBoxLayout(); r3.addWidget(self._s_cert); r3.addWidget(b3)
        form.addRow("Certificate:", r3)

        self._s_out = QLineEdit(); self._s_out.setPlaceholderText("output.p7s")
        b4 = QPushButton("Browse…"); b4.setMaximumWidth(80); b4.clicked.connect(lambda: self._browse(self._s_out, save=True))
        r4 = QHBoxLayout(); r4.addWidget(self._s_out); r4.addWidget(b4)
        form.addRow("Signature Output:", r4)

        self._s_pass = QLineEdit(); self._s_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Key Passphrase:", self._s_pass)

        self._s_digest = QComboBox(); self._s_digest.addItems(["sha256", "sha384", "sha512"])
        form.addRow("Digest:", self._s_digest)
        l.addLayout(form)

        btn = QPushButton("Sign File")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_sign)
        l.addWidget(btn)

        self._s_status = self.build_status_label()
        l.addWidget(self._s_status)
        _, self._s_out_text = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_sign(self):
        f = self._s_file.text().strip(); k = self._s_key.text().strip()
        c = self._s_cert.text().strip(); o = self._s_out.text().strip()
        if not all([f, k, c, o]):
            return
        passphrase = self._s_pass.text() or None
        digest = self._s_digest.currentText()
        self.run_in_thread(sign_file, f, k, c, o, digest, passphrase, callback=self._on_sign_done)

    def _on_sign_done(self, r):
        self.show_result(r, self._s_out_text, self._s_status)

    # ------------------------------------------------------------------
    def _build_verify_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        form = QFormLayout()

        self._v_file = QLineEdit(); self._v_file.setPlaceholderText("Original file")
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._v_file))
        r1 = QHBoxLayout(); r1.addWidget(self._v_file); r1.addWidget(b1)
        form.addRow("File:", r1)

        self._v_sig = QLineEdit(); self._v_sig.setPlaceholderText("Signature file .p7s")
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._v_sig))
        r2 = QHBoxLayout(); r2.addWidget(self._v_sig); r2.addWidget(b2)
        form.addRow("Signature:", r2)

        self._v_ca = QLineEdit(); self._v_ca.setPlaceholderText("CA bundle .pem (optional)")
        b3 = QPushButton("Browse…"); b3.setMaximumWidth(80); b3.clicked.connect(lambda: self._browse(self._v_ca))
        r3 = QHBoxLayout(); r3.addWidget(self._v_ca); r3.addWidget(b3)
        form.addRow("CA Bundle:", r3)
        l.addLayout(form)

        btn = QPushButton("Verify Signature")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_verify)
        l.addWidget(btn)

        self._v_status = self.build_status_label()
        l.addWidget(self._v_status)
        _, self._v_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_verify(self):
        f = self._v_file.text().strip(); s = self._v_sig.text().strip()
        ca = self._v_ca.text().strip() or None
        if not f or not s:
            return
        self.run_in_thread(verify_file, f, s, ca, callback=self._on_verify_done)

    def _on_verify_done(self, r):
        if r.parsed.get("verified"):
            self._v_status.setText("✓  VALID SIGNATURE")
            self._v_status.setStyleSheet("color: #34D399; font-weight: bold; font-size: 13px;")
        else:
            self._v_status.setText("✗  INVALID or UNVERIFIED SIGNATURE")
            self._v_status.setStyleSheet("color: #F87171; font-weight: bold; font-size: 13px;")
        self._v_out.setPlainText(r.output)

    # ------------------------------------------------------------------
    def _build_raw_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        info = QLabel("Raw ECDSA/RSA signature — used for firmware signing (RP2350) and similar use cases.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        l.addWidget(info)

        form = QFormLayout()
        self._r_file = QLineEdit(); self._r_file.setPlaceholderText("File to sign")
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._r_file))
        r1 = QHBoxLayout(); r1.addWidget(self._r_file); r1.addWidget(b1)
        form.addRow("File:", r1)

        self._r_key = QLineEdit()
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._r_key))
        vault_btn_r = QPushButton("🔒 Vault"); vault_btn_r.setMaximumWidth(64)
        vault_btn_r.setToolTip("Use a key from the encrypted Key Vault")
        vault_btn_r.clicked.connect(lambda: self._use_vault_key(self._r_key))
        r2 = QHBoxLayout(); r2.addWidget(self._r_key); r2.addWidget(b2); r2.addWidget(vault_btn_r)
        form.addRow("Private Key:", r2)

        self._r_sig_out = QLineEdit(); self._r_sig_out.setPlaceholderText("signature.bin")
        b3 = QPushButton("Browse…"); b3.setMaximumWidth(80); b3.clicked.connect(lambda: self._browse(self._r_sig_out, save=True))
        r3 = QHBoxLayout(); r3.addWidget(self._r_sig_out); r3.addWidget(b3)
        form.addRow("Signature Output:", r3)
        l.addLayout(form)

        row_btns = QHBoxLayout()
        btn_sign = QPushButton("Sign")
        btn_sign.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn_sign.clicked.connect(self._do_raw_sign)

        self._r_pub = QLineEdit(); self._r_pub.setPlaceholderText("Public key .pem (for verify)")
        b4 = QPushButton("Browse…"); b4.setMaximumWidth(80); b4.clicked.connect(lambda: self._browse(self._r_pub))
        r4 = QHBoxLayout(); r4.addWidget(self._r_pub); r4.addWidget(b4)
        form.addRow("Public Key:", r4)
        btn_verify = QPushButton("Verify")
        btn_verify.setStyleSheet("background:#065F46; color:white; padding:8px; border-radius:6px;")
        btn_verify.clicked.connect(self._do_raw_verify)
        row_btns.addWidget(btn_sign); row_btns.addWidget(btn_verify)
        l.addLayout(row_btns)

        self._r_status = self.build_status_label()
        l.addWidget(self._r_status)
        _, self._r_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_raw_sign(self):
        f = self._r_file.text().strip(); k = self._r_key.text().strip()
        o = self._r_sig_out.text().strip()
        if not all([f, k, o]):
            return
        self.run_in_thread(sign_raw, f, k, o, callback=self._on_raw_done)

    def _do_raw_verify(self):
        f = self._r_file.text().strip(); s = self._r_sig_out.text().strip()
        pub = self._r_pub.text().strip()
        if not all([f, s, pub]):
            return
        self.run_in_thread(verify_raw, f, s, pub, callback=self._on_raw_done)

    def _on_raw_done(self, r):
        self.show_result(r, self._r_out, self._r_status)

    # ------------------------------------------------------------------
    def _build_pico_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        info = QLabel(
            "Verify .bin.signed firmware files produced by the Earle Philhower RP2350 "
            "signing pipeline (openssl dgst -sha256 -sign).\n\n"
            "Format: raw binary + DER-encoded ECDSA-P256 signature + 4-byte length marker (0x00010000)."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        l.addWidget(info)

        form = QFormLayout()
        self._pico_bin = QLineEdit(); self._pico_bin.setPlaceholderText("firmware.bin.signed")
        b1 = QPushButton("Browse…"); b1.setMaximumWidth(80); b1.clicked.connect(lambda: self._browse(self._pico_bin))
        r1 = QHBoxLayout(); r1.addWidget(self._pico_bin); r1.addWidget(b1)
        form.addRow(".bin.signed file:", r1)

        self._pico_pub = QLineEdit(); self._pico_pub.setPlaceholderText("public.key (EC P-256)")
        b2 = QPushButton("Browse…"); b2.setMaximumWidth(80); b2.clicked.connect(lambda: self._browse(self._pico_pub))
        r2 = QHBoxLayout(); r2.addWidget(self._pico_pub); r2.addWidget(b2)
        form.addRow("Public Key:", r2)
        l.addLayout(form)

        btn = QPushButton("Verify Firmware Signature")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_pico_verify)
        l.addWidget(btn)

        self._pico_status = self.build_status_label()
        l.addWidget(self._pico_status)
        _, self._pico_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_pico_verify(self):
        f = self._pico_bin.text().strip()
        pub = self._pico_pub.text().strip()
        if not f or not pub:
            return
        self.run_in_thread(verify_bin_signed, f, pub, callback=self._on_pico_done)

    def _on_pico_done(self, r):
        if r.parsed.get("verified") or r.success:
            self._pico_status.setText("✓  FIRMWARE SIGNATURE VALID — safe to distribute")
            self._pico_status.setStyleSheet("color: #34D399; font-weight: bold; font-size: 13px;")
        else:
            self._pico_status.setText("✗  INVALID SIGNATURE — do not distribute")
            self._pico_status.setStyleSheet("color: #F87171; font-weight: bold; font-size: 13px;")
        p = r.parsed
        self._pico_out.setPlainText(
            f"Firmware body: {p.get('firmware_size_bytes', '?')} bytes\n"
            f"Signature: {p.get('signature_size_bytes', '?')} bytes (DER ECDSA-P256)\n"
            f"Total .bin.signed: {p.get('total_file_size', '?')} bytes\n\n"
            + r.output
        )
