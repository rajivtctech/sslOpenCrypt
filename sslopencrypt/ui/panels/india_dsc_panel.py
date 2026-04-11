"""
ui/panels/india_dsc_panel.py — Module 10: India DSC & eSign.

Provides:
  Tab 1 — DSC Token Manager: detect tokens, list objects, export certificate
  Tab 2 — Sign Document: on-token CMS signing (private key stays on hardware)
  Tab 3 — Verify Signature: validate against India PKI chain
  Tab 4 — India PKI Info: RCAI fingerprint, licensed CAs, setup commands
"""

from PyQt6.QtWidgets import (
    QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)
from PyQt6.QtCore import Qt

from modules.india_dsc.controller import (
    check_dependencies, list_tokens, list_objects,
    export_certificate, inspect_certificate,
    sign_file_with_token, verify_signature_india_pki,
    get_india_pki_info, detect_available_libs,
    KNOWN_TOKEN_LIBS,
)
from .base_panel import BasePanel


class IndiaDSCPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🇮🇳  India DSC & eSign")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        desc = QLabel(
            "USB token PKCS#11 integration for India Class 3 Digital Signature Certificates.\n"
            "Supports ePass2003 / HYP2003, SafeNet eToken, HyperPKI, and OpenSC-compatible tokens."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(desc)

        tabs = QTabWidget()
        tabs.addTab(self._build_token_tab(), "Token Manager")
        tabs.addTab(self._build_sign_tab(), "Sign Document")
        tabs.addTab(self._build_verify_tab(), "Verify Signature")
        tabs.addTab(self._build_info_tab(), "India PKI Info")
        layout.addWidget(tabs, stretch=1)

    # ------------------------------------------------------------------
    # Tab 1 — Token Manager
    # ------------------------------------------------------------------

    def _build_token_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        # Dependency check banner
        self._dep_banner = QLabel()
        self._dep_banner.setWordWrap(True)
        self._dep_banner.setStyleSheet(
            "background:#1E3A5F; border:1px solid #3B82F6; "
            "border-radius:6px; color:#BFDBFE; font-size:10px; padding:8px;"
        )
        l.addWidget(self._dep_banner)

        btn_dep = QPushButton("Check Dependencies")
        btn_dep.setStyleSheet("background:#374151; color:#E5E7EB; padding:6px 12px;")
        btn_dep.clicked.connect(self._do_check_deps)
        l.addWidget(btn_dep)

        form = QFormLayout()
        form.setSpacing(8)

        self._tok_lib = QComboBox()
        self._tok_lib.setEditable(True)
        # Populate with known libs that exist on this system
        available = [(name, path) for name, path, present in detect_available_libs() if present]
        all_libs = [(name, path) for name, path in KNOWN_TOKEN_LIBS]
        items = available if available else all_libs
        for name, path in items:
            self._tok_lib.addItem(f"{name}  —  {path}", path)
        form.addRow("Token library:", self._tok_lib)

        self._tok_pin = QLineEdit()
        self._tok_pin.setEchoMode(QLineEdit.EchoMode.Password)
        self._tok_pin.setPlaceholderText("Token PIN (required for list-objects and export)")
        form.addRow("PIN:", self._tok_pin)

        l.addLayout(form)

        btns = QHBoxLayout()
        btn_slots = QPushButton("List Tokens / Slots")
        btn_slots.setStyleSheet("background:#374151; color:#E5E7EB; padding:7px;")
        btn_slots.clicked.connect(self._do_list_tokens)

        btn_objs = QPushButton("List Objects (needs PIN)")
        btn_objs.setStyleSheet("background:#374151; color:#E5E7EB; padding:7px;")
        btn_objs.clicked.connect(self._do_list_objects)
        btns.addWidget(btn_slots)
        btns.addWidget(btn_objs)
        l.addLayout(btns)

        # Export cert
        export_row = QHBoxLayout()
        self._tok_cert_out = QLineEdit()
        self._tok_cert_out.setPlaceholderText("Export certificate to… (PEM file)")
        btn_browse = QPushButton("Browse…")
        btn_browse.setMaximumWidth(80)
        btn_browse.clicked.connect(lambda: self._browse_save(self._tok_cert_out))
        export_row.addWidget(self._tok_cert_out)
        export_row.addWidget(btn_browse)

        self._tok_cert_label = QLineEdit("Certificate")
        self._tok_cert_label.setPlaceholderText("Object label on token (default: Certificate)")
        self._tok_cert_label.setMaximumWidth(180)

        btn_export = QPushButton("Export Certificate")
        btn_export.setStyleSheet("background:#1D4ED8; color:white; padding:7px; border-radius:4px;")
        btn_export.clicked.connect(self._do_export_cert)

        l.addLayout(export_row)
        lbl_row = QHBoxLayout()
        lbl_row.addWidget(QLabel("Cert label:"))
        lbl_row.addWidget(self._tok_cert_label)
        lbl_row.addWidget(btn_export)
        l.addLayout(lbl_row)

        self._tok_status = self.build_status_label()
        l.addWidget(self._tok_status)
        _, self._tok_out = self.build_output_area("Output")
        l.addWidget(_, stretch=1)

        # Initial dep check hint
        self._dep_banner.setText(
            "Click 'Check Dependencies' to verify pkcs11-tool and pcscd are installed.\n"
            "Install: sudo apt install opensc pcscd && sudo systemctl start pcscd"
        )
        return w

    def _get_lib_path(self) -> str:
        data = self._tok_lib.currentData()
        return data if data else self._tok_lib.currentText().split("—")[-1].strip()

    def _browse_save(self, edit: QLineEdit):
        path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "PEM Files (*.pem);;All Files (*)")
        if path:
            edit.setText(path)

    def _browse_open(self, edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _do_check_deps(self):
        self.run_in_thread(check_dependencies, callback=self._on_dep_done)

    def _on_dep_done(self, r):
        if r.success:
            n = len(r.parsed.get("available_token_libs", []))
            self._dep_banner.setText(
                f"✓  Dependencies OK — pkcs11-tool found, pcscd running.\n"
                f"   {n} token library/libraries detected on this system."
            )
            self._dep_banner.setStyleSheet(
                "background:#064E3B; border:1px solid #34D399; "
                "border-radius:6px; color:#D1FAE5; font-size:10px; padding:8px;"
            )
        else:
            self._dep_banner.setText(f"✗  {r.stderr}")
            self._dep_banner.setStyleSheet(
                "background:#7F1D1D; border:1px solid #F87171; "
                "border-radius:6px; color:#FEE2E2; font-size:10px; padding:8px;"
            )

    def _do_list_tokens(self):
        lib = self._get_lib_path()
        self.run_in_thread(list_tokens, lib, callback=self._on_tok_done)

    def _do_list_objects(self):
        lib = self._get_lib_path()
        pin = self._tok_pin.text()
        self.run_in_thread(list_objects, lib, pin, callback=self._on_tok_done)

    def _do_export_cert(self):
        lib = self._get_lib_path()
        out = self._tok_cert_out.text().strip()
        label = self._tok_cert_label.text().strip() or "Certificate"
        pin = self._tok_pin.text()
        if not out:
            self._tok_status.setText("✗  Specify an output file path")
            return
        self.run_in_thread(export_certificate, lib, out, label, pin, callback=self._on_tok_done)

    def _on_tok_done(self, r):
        self.show_result(r, self._tok_out, self._tok_status)

    # ------------------------------------------------------------------
    # Tab 2 — Sign Document
    # ------------------------------------------------------------------

    def _build_sign_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        note = QLabel(
            "The private key NEVER leaves the token. Signing happens inside the hardware.\n"
            "You must have previously exported your certificate (Tab 1) to use as the -signer argument."
        )
        note.setWordWrap(True)
        note.setStyleSheet(
            "background:#1E3A5F; border:1px solid #3B82F6; border-radius:6px; "
            "color:#BFDBFE; font-size:10px; padding:8px;"
        )
        l.addWidget(note)

        form = QFormLayout()
        form.setSpacing(8)

        self._sig_lib = QComboBox()
        self._sig_lib.setEditable(True)
        for name, path in KNOWN_TOKEN_LIBS:
            if Path(path).exists():
                self._sig_lib.addItem(f"{name}", path)
        if self._sig_lib.count() == 0:
            for name, path in KNOWN_TOKEN_LIBS[:2]:
                self._sig_lib.addItem(f"{name}", path)
        form.addRow("Token library:", self._sig_lib)

        self._sig_cert = QLineEdit()
        self._sig_cert.setPlaceholderText("Signer certificate (.pem) — exported from token in Tab 1")
        btn_cert = QPushButton("Browse…")
        btn_cert.setMaximumWidth(80)
        btn_cert.clicked.connect(lambda: self._browse_open(self._sig_cert))
        row_cert = QHBoxLayout()
        row_cert.addWidget(self._sig_cert)
        row_cert.addWidget(btn_cert)
        form.addRow("Signer cert:", row_cert)

        self._sig_doc = QLineEdit()
        self._sig_doc.setPlaceholderText("Document to sign (.pdf, .txt, .xml…)")
        btn_doc = QPushButton("Browse…")
        btn_doc.setMaximumWidth(80)
        btn_doc.clicked.connect(lambda: self._browse_open(self._sig_doc))
        row_doc = QHBoxLayout()
        row_doc.addWidget(self._sig_doc)
        row_doc.addWidget(btn_doc)
        form.addRow("Document:", row_doc)

        self._sig_out = QLineEdit()
        self._sig_out.setPlaceholderText("Output signature file (.p7s)")
        btn_out = QPushButton("Browse…")
        btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse_save(self._sig_out))
        row_out = QHBoxLayout()
        row_out.addWidget(self._sig_out)
        row_out.addWidget(btn_out)
        form.addRow("Output sig:", row_out)

        self._sig_keylabel = QLineEdit("Private Key")
        self._sig_keylabel.setPlaceholderText("Key label on token (default: Private Key)")
        form.addRow("Key label:", self._sig_keylabel)

        self._sig_pin = QLineEdit()
        self._sig_pin.setEchoMode(QLineEdit.EchoMode.Password)
        self._sig_pin.setPlaceholderText("Token PIN")
        form.addRow("PIN:", self._sig_pin)

        l.addLayout(form)

        btn_sign = QPushButton("Sign with Token")
        btn_sign.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px; font-weight:bold;")
        btn_sign.clicked.connect(self._do_sign)
        l.addWidget(btn_sign)

        self._sign_status = self.build_status_label()
        l.addWidget(self._sign_status)
        _, self._sign_out_text = self.build_output_area("Result / Command")
        l.addWidget(_, stretch=1)
        return w

    def _do_sign(self):
        lib = self._sig_lib.currentData() or self._sig_lib.currentText()
        cert = self._sig_cert.text().strip()
        doc = self._sig_doc.text().strip()
        out = self._sig_out.text().strip()
        key_label = self._sig_keylabel.text().strip() or "Private Key"
        pin = self._sig_pin.text()
        if not all([cert, doc, out]):
            self._sign_status.setText("✗  Fill in cert, document, and output fields")
            self._sign_status.setStyleSheet("color:#F87171;")
            return
        self.run_in_thread(
            sign_file_with_token, lib, cert, doc, out, key_label, pin,
            callback=lambda r: self.show_result(r, self._sign_out_text, self._sign_status),
        )

    # ------------------------------------------------------------------
    # Tab 3 — Verify Signature
    # ------------------------------------------------------------------

    def _build_verify_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)

        self._ver_sig = QLineEdit()
        self._ver_sig.setPlaceholderText("Signature file (.p7s) in DER format")
        btn_sig = QPushButton("Browse…")
        btn_sig.setMaximumWidth(80)
        btn_sig.clicked.connect(lambda: self._browse_open(self._ver_sig))
        row_sig = QHBoxLayout()
        row_sig.addWidget(self._ver_sig)
        row_sig.addWidget(btn_sig)
        form.addRow("Signature:", row_sig)

        self._ver_doc = QLineEdit()
        self._ver_doc.setPlaceholderText("Original document that was signed")
        btn_doc = QPushButton("Browse…")
        btn_doc.setMaximumWidth(80)
        btn_doc.clicked.connect(lambda: self._browse_open(self._ver_doc))
        row_doc = QHBoxLayout()
        row_doc.addWidget(self._ver_doc)
        row_doc.addWidget(btn_doc)
        form.addRow("Document:", row_doc)

        self._ver_ca = QLineEdit()
        self._ver_ca.setPlaceholderText("CA bundle (optional — India PKI chain PEM)")
        btn_ca = QPushButton("Browse…")
        btn_ca.setMaximumWidth(80)
        btn_ca.clicked.connect(lambda: self._browse_open(self._ver_ca))
        row_ca = QHBoxLayout()
        row_ca.addWidget(self._ver_ca)
        row_ca.addWidget(btn_ca)
        form.addRow("CA bundle:", row_ca)

        l.addLayout(form)

        btn_verify = QPushButton("Verify Signature")
        btn_verify.setStyleSheet("background:#065F46; color:white; padding:8px; border-radius:6px; font-weight:bold;")
        btn_verify.clicked.connect(self._do_verify)
        l.addWidget(btn_verify)

        self._ver_status = self.build_status_label()
        l.addWidget(self._ver_status)
        _, self._ver_out = self.build_output_area("Verification Result")
        l.addWidget(_, stretch=1)
        return w

    def _do_verify(self):
        sig = self._ver_sig.text().strip()
        doc = self._ver_doc.text().strip()
        ca = self._ver_ca.text().strip()
        if not sig or not doc:
            self._ver_status.setText("✗  Provide signature file and document")
            return
        self.run_in_thread(
            verify_signature_india_pki, sig, doc, ca,
            callback=lambda r: self.show_result(r, self._ver_out, self._ver_status),
        )

    # ------------------------------------------------------------------
    # Tab 4 — India PKI Info
    # ------------------------------------------------------------------

    def _build_info_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        info = get_india_pki_info()

        text = QTextEdit()
        text.setReadOnly(True)
        from PyQt6.QtGui import QFont
        text.setFont(QFont("Monospace", 9))
        text.setStyleSheet(
            "background:#111827; color:#D1FAE5; border:1px solid #374151; border-radius:4px;"
        )

        content = "INDIA PKI TRUST STORE — REFERENCE\n" + "=" * 60 + "\n\n"
        content += f"RCAI (Root Certifying Authority of India)\n"
        content += f"  URL: {info['rcai_url']}\n"
        content += f"  SHA-256 Fingerprint (verify out-of-band at cca.gov.in):\n"
        content += f"  {info['rcai_fingerprint_sha256']}\n\n"
        content += f"CCA Licensed CAs: {info['cca_url']}\n\n"

        content += "LICENSED CERTIFYING AUTHORITIES\n" + "-" * 40 + "\n"
        for ca in info["licensed_cas"]:
            content += f"  {ca['name']:<35} {ca['type']}  {ca['website']}\n"

        content += "\nCURRENT REQUIREMENTS\n" + "-" * 40 + "\n"
        content += f"  Algorithm:       {info['algorithm_requirement']}\n"
        content += f"  Token standard:  {info['token_standard']}\n"
        content += f"  KYC:             {info['kyc_requirement']}\n"
        content += f"  Class 2 status:  {info['class2_discontinued']}\n"

        content += "\nSETUP COMMANDS (Linux)\n" + "-" * 40 + "\n"
        content += "  sudo apt install opensc pcscd pcsc-tools\n"
        content += "  sudo systemctl enable --now pcscd\n"
        content += "  pcsc_scan                            # verify token detected\n"
        content += "  pkcs11-tool --module <vendor.so> -L  # list slots\n"
        content += "\nCOMMON TOKEN LIBRARY PATHS\n" + "-" * 40 + "\n"
        for name, path, present in detect_available_libs():
            status = "✓ found" if present else "  absent"
            content += f"  [{status}]  {name}\n             {path}\n"

        text.setPlainText(content)
        l.addWidget(text, stretch=1)
        return w

    # ------------------------------------------------------------------

    def set_expert_mode(self, expert: bool):
        pass  # All tabs visible in both modes


# Needed for Path import inside the panel
from pathlib import Path
