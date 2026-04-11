"""
ui/panels/pki_panel.py — Module 4: PKI & Certificate Management panel.
"""

from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget,
)

from modules.pki.controller import (
    create_csr, create_self_signed, create_root_ca,
    sign_csr, inspect_cert, create_pkcs12, inspect_tls, verify_cert_chain,
)
from .base_panel import BasePanel


class PKIPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("📜  PKI & Certificate Management")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_csr_tab(), "CSR Builder")
        tabs.addTab(self._build_selfsigned_tab(), "Self-Signed Cert")
        tabs.addTab(self._build_ca_tab(), "CA Manager")
        tabs.addTab(self._build_inspect_tab(), "Inspect Cert")
        tabs.addTab(self._build_pkcs12_tab(), "PKCS#12 Bundle")
        tabs.addTab(self._build_tls_tab(), "TLS Inspector")
        layout.addWidget(tabs, stretch=1)

    def _browse(self, edit: QLineEdit, save: bool = False):
        if save:
            path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "PEM Files (*.pem);;All Files (*)")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open File", "", "PEM Files (*.pem);;All Files (*)")
        if path:
            edit.setText(path)

    # ------------------------------------------------------------------
    # CSR Builder
    # ------------------------------------------------------------------

    def _build_csr_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(6)

        form = QFormLayout()
        self._csr_cn = QLineEdit(); self._csr_cn.setPlaceholderText("example.com")
        form.addRow("Common Name (CN):", self._csr_cn)
        self._csr_org = QLineEdit(); self._csr_org.setPlaceholderText("My Organisation Ltd")
        form.addRow("Organisation (O):", self._csr_org)
        self._csr_ou = QLineEdit(); self._csr_ou.setPlaceholderText("IT Department")
        form.addRow("Org Unit (OU):", self._csr_ou)
        self._csr_country = QLineEdit(); self._csr_country.setPlaceholderText("IN")
        self._csr_country.setMaximumWidth(50)
        form.addRow("Country (C):", self._csr_country)
        self._csr_state = QLineEdit(); self._csr_state.setPlaceholderText("Uttar Pradesh")
        form.addRow("State (ST):", self._csr_state)
        self._csr_loc = QLineEdit(); self._csr_loc.setPlaceholderText("Meerut")
        form.addRow("Locality (L):", self._csr_loc)
        self._csr_email = QLineEdit(); self._csr_email.setPlaceholderText("admin@example.com")
        form.addRow("Email:", self._csr_email)

        self._csr_san = QLineEdit()
        self._csr_san.setPlaceholderText("DNS:example.com, DNS:www.example.com, IP:10.0.0.1")
        form.addRow("SANs:", self._csr_san)
        form.addRow(QLabel("  (comma-separated: DNS:... IP:... email:... URI:...)"),)

        self._csr_key = QLineEdit(); self._csr_key.setPlaceholderText("Private key .pem")
        btn_key = QPushButton("Browse…"); btn_key.setMaximumWidth(80)
        btn_key.clicked.connect(lambda: self._browse(self._csr_key))
        row_key = QHBoxLayout(); row_key.addWidget(self._csr_key); row_key.addWidget(btn_key)
        form.addRow("Private Key:", row_key)

        self._csr_pass = QLineEdit(); self._csr_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._csr_pass.setPlaceholderText("Key passphrase (if encrypted)")
        form.addRow("Key Passphrase:", self._csr_pass)

        self._csr_out = QLineEdit(); self._csr_out.setPlaceholderText("output.csr")
        btn_out = QPushButton("Browse…"); btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse(self._csr_out, save=True))
        row_out = QHBoxLayout(); row_out.addWidget(self._csr_out); row_out.addWidget(btn_out)
        form.addRow("CSR Output:", row_out)

        l.addLayout(form)

        btn = QPushButton("Generate CSR")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_csr)
        l.addWidget(btn)

        self._csr_status = self.build_status_label()
        l.addWidget(self._csr_status)
        _, self._csr_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_csr(self):
        key = self._csr_key.text().strip()
        out = self._csr_out.text().strip()
        if not key or not out:
            self._csr_status.setText("✗  Key file and output path required")
            self._csr_status.setStyleSheet("color: #F87171;")
            return
        subject = {
            "CN": self._csr_cn.text().strip(),
            "O": self._csr_org.text().strip(),
            "OU": self._csr_ou.text().strip(),
            "C": self._csr_country.text().strip(),
            "ST": self._csr_state.text().strip(),
            "L": self._csr_loc.text().strip(),
            "emailAddress": self._csr_email.text().strip(),
        }
        san_text = self._csr_san.text().strip()
        san_list = [s.strip() for s in san_text.split(",") if s.strip()] if san_text else None
        passphrase = self._csr_pass.text() or None

        self.run_in_thread(create_csr, key, out, subject, san_list, passphrase, callback=self._on_csr_done)

    def _on_csr_done(self, r):
        self.show_result(r, self._csr_output, self._csr_status)

    # ------------------------------------------------------------------
    # Self-Signed
    # ------------------------------------------------------------------

    def _build_selfsigned_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(6)

        form = QFormLayout()
        self._ss_cn = QLineEdit(); self._ss_cn.setPlaceholderText("example.com")
        form.addRow("CN:", self._ss_cn)
        self._ss_org = QLineEdit()
        form.addRow("Organisation:", self._ss_org)
        self._ss_country = QLineEdit(); self._ss_country.setPlaceholderText("IN"); self._ss_country.setMaximumWidth(50)
        form.addRow("Country:", self._ss_country)

        self._ss_days = QSpinBox(); self._ss_days.setRange(1, 36500); self._ss_days.setValue(365)
        form.addRow("Validity (days):", self._ss_days)

        self._ss_san = QLineEdit(); self._ss_san.setPlaceholderText("DNS:example.com, IP:127.0.0.1")
        form.addRow("SANs:", self._ss_san)

        self._ss_key = QLineEdit()
        btn_key = QPushButton("Browse…"); btn_key.setMaximumWidth(80)
        btn_key.clicked.connect(lambda: self._browse(self._ss_key))
        row = QHBoxLayout(); row.addWidget(self._ss_key); row.addWidget(btn_key)
        form.addRow("Private Key:", row)

        self._ss_pass = QLineEdit(); self._ss_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Key Passphrase:", self._ss_pass)

        self._ss_out = QLineEdit(); self._ss_out.setPlaceholderText("cert.pem")
        btn_out = QPushButton("Browse…"); btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse(self._ss_out, save=True))
        row_o = QHBoxLayout(); row_o.addWidget(self._ss_out); row_o.addWidget(btn_out)
        form.addRow("Cert Output:", row_o)

        l.addLayout(form)

        btn = QPushButton("Create Self-Signed Certificate")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_selfsigned)
        l.addWidget(btn)

        self._ss_status = self.build_status_label()
        l.addWidget(self._ss_status)
        _, self._ss_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_selfsigned(self):
        key = self._ss_key.text().strip()
        out = self._ss_out.text().strip()
        if not key or not out:
            return
        subject = {
            "CN": self._ss_cn.text().strip(),
            "O": self._ss_org.text().strip(),
            "C": self._ss_country.text().strip(),
        }
        san_text = self._ss_san.text().strip()
        san_list = [s.strip() for s in san_text.split(",") if s.strip()] if san_text else None
        passphrase = self._ss_pass.text() or None
        days = self._ss_days.value()
        self.run_in_thread(create_self_signed, key, out, subject, days, san_list, passphrase, callback=self._on_ss_done)

    def _on_ss_done(self, r):
        self.show_result(r, self._ss_output, self._ss_status)

    # ------------------------------------------------------------------
    # CA Manager (simplified)
    # ------------------------------------------------------------------

    def _build_ca_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        info = QLabel("Create a Root CA certificate (self-signed, CA:TRUE).\nThen use 'Sign CSR' to issue end-entity certificates.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        l.addWidget(info)

        form = QFormLayout()
        self._ca_cn = QLineEdit(); self._ca_cn.setPlaceholderText("My Root CA")
        form.addRow("CA Name (CN):", self._ca_cn)
        self._ca_org = QLineEdit()
        form.addRow("Organisation:", self._ca_org)
        self._ca_country = QLineEdit(); self._ca_country.setPlaceholderText("IN"); self._ca_country.setMaximumWidth(50)
        form.addRow("Country:", self._ca_country)
        self._ca_days = QSpinBox(); self._ca_days.setRange(365, 36500); self._ca_days.setValue(3650)
        form.addRow("Validity (days):", self._ca_days)

        self._ca_key = QLineEdit()
        btn_key = QPushButton("Browse…"); btn_key.setMaximumWidth(80)
        btn_key.clicked.connect(lambda: self._browse(self._ca_key))
        row = QHBoxLayout(); row.addWidget(self._ca_key); row.addWidget(btn_key)
        form.addRow("CA Private Key:", row)

        self._ca_key_pass = QLineEdit(); self._ca_key_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Key Passphrase:", self._ca_key_pass)

        self._ca_cert_out = QLineEdit(); self._ca_cert_out.setPlaceholderText("ca_cert.pem")
        btn_out = QPushButton("Browse…"); btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(lambda: self._browse(self._ca_cert_out, save=True))
        row_o = QHBoxLayout(); row_o.addWidget(self._ca_cert_out); row_o.addWidget(btn_out)
        form.addRow("CA Cert Output:", row_o)

        l.addLayout(form)

        btn_create = QPushButton("Create Root CA")
        btn_create.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn_create.clicked.connect(self._do_create_ca)
        l.addWidget(btn_create)

        # Sign CSR section
        sep = QLabel("── Sign a CSR with this CA ──")
        sep.setStyleSheet("color: #6B7280; font-size: 10px; margin-top: 8px;")
        l.addWidget(sep)

        form2 = QFormLayout()
        self._ca_csr_in = QLineEdit(); self._ca_csr_in.setPlaceholderText("certificate_request.csr")
        btn_csr = QPushButton("Browse…"); btn_csr.setMaximumWidth(80)
        btn_csr.clicked.connect(lambda: self._browse(self._ca_csr_in))
        row_csr = QHBoxLayout(); row_csr.addWidget(self._ca_csr_in); row_csr.addWidget(btn_csr)
        form2.addRow("CSR File:", row_csr)

        self._ca_signed_out = QLineEdit(); self._ca_signed_out.setPlaceholderText("signed_cert.pem")
        btn_so = QPushButton("Browse…"); btn_so.setMaximumWidth(80)
        btn_so.clicked.connect(lambda: self._browse(self._ca_signed_out, save=True))
        row_so = QHBoxLayout(); row_so.addWidget(self._ca_signed_out); row_so.addWidget(btn_so)
        form2.addRow("Signed Cert Output:", row_so)

        self._ca_sign_days = QSpinBox(); self._ca_sign_days.setRange(1, 3650); self._ca_sign_days.setValue(365)
        form2.addRow("Validity (days):", self._ca_sign_days)
        l.addLayout(form2)

        btn_sign = QPushButton("Sign CSR")
        btn_sign.setStyleSheet("background:#065F46; color:white; padding:8px; border-radius:6px;")
        btn_sign.clicked.connect(self._do_sign_csr)
        l.addWidget(btn_sign)

        self._ca_status = self.build_status_label()
        l.addWidget(self._ca_status)
        _, self._ca_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_create_ca(self):
        key = self._ca_key.text().strip()
        out = self._ca_cert_out.text().strip()
        if not key or not out:
            return
        subject = {"CN": self._ca_cn.text().strip(), "O": self._ca_org.text().strip(), "C": self._ca_country.text().strip()}
        passphrase = self._ca_key_pass.text() or None
        self.run_in_thread(create_root_ca, key, out, subject, self._ca_days.value(), passphrase, callback=self._on_ca_done)

    def _do_sign_csr(self):
        ca_cert = self._ca_cert_out.text().strip()
        ca_key = self._ca_key.text().strip()
        csr = self._ca_csr_in.text().strip()
        out = self._ca_signed_out.text().strip()
        if not all([ca_cert, ca_key, csr, out]):
            return
        passphrase = self._ca_key_pass.text() or None
        self.run_in_thread(sign_csr, ca_cert, ca_key, csr, out, self._ca_sign_days.value(), passphrase, callback=self._on_ca_done)

    def _on_ca_done(self, r):
        self.show_result(r, self._ca_output, self._ca_status)

    # ------------------------------------------------------------------
    # Inspect Cert
    # ------------------------------------------------------------------

    def _build_inspect_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._ic_path = QLineEdit(); self._ic_path.setPlaceholderText("certificate.pem or .crt")
        btn = QPushButton("Browse…"); btn.setMaximumWidth(80)
        btn.clicked.connect(lambda: self._browse(self._ic_path))
        row = QHBoxLayout(); row.addWidget(self._ic_path); row.addWidget(btn)
        form.addRow("Certificate:", row)
        l.addLayout(form)

        btn_insp = QPushButton("Inspect Certificate")
        btn_insp.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn_insp.clicked.connect(self._do_inspect)
        l.addWidget(btn_insp)

        self._ic_status = self.build_status_label()
        l.addWidget(self._ic_status)
        _, self._ic_output = self.build_output_area("Certificate Details")
        l.addWidget(_, stretch=1)
        return w

    def _do_inspect(self):
        path = self._ic_path.text().strip()
        if not path:
            return
        self.run_in_thread(inspect_cert, path, callback=self._on_inspect_done)

    def _on_inspect_done(self, r):
        self.show_result(r, self._ic_output, self._ic_status)
        if r.success and r.parsed:
            parsed_text = "\n".join(f"{k:20}: {v}" for k, v in r.parsed.items())
            self._ic_output.setPlainText(parsed_text + "\n\n" + r.stdout)

    # ------------------------------------------------------------------
    # PKCS#12
    # ------------------------------------------------------------------

    def _build_pkcs12_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(6)

        form = QFormLayout()
        self._p12_cert = QLineEdit()
        btn1 = QPushButton("Browse…"); btn1.setMaximumWidth(80)
        btn1.clicked.connect(lambda: self._browse(self._p12_cert))
        r1 = QHBoxLayout(); r1.addWidget(self._p12_cert); r1.addWidget(btn1)
        form.addRow("Certificate:", r1)

        self._p12_key = QLineEdit()
        btn2 = QPushButton("Browse…"); btn2.setMaximumWidth(80)
        btn2.clicked.connect(lambda: self._browse(self._p12_key))
        r2 = QHBoxLayout(); r2.addWidget(self._p12_key); r2.addWidget(btn2)
        form.addRow("Private Key:", r2)

        self._p12_out = QLineEdit(); self._p12_out.setPlaceholderText("bundle.p12")
        btn3 = QPushButton("Browse…"); btn3.setMaximumWidth(80)
        btn3.clicked.connect(lambda: self._browse(self._p12_out, save=True))
        r3 = QHBoxLayout(); r3.addWidget(self._p12_out); r3.addWidget(btn3)
        form.addRow("Output .p12:", r3)

        self._p12_pass = QLineEdit(); self._p12_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._p12_pass.setPlaceholderText("PKCS#12 export password")
        form.addRow("Export Password:", self._p12_pass)

        self._p12_name = QLineEdit(); self._p12_name.setText("sslOpenCrypt")
        form.addRow("Friendly Name:", self._p12_name)
        l.addLayout(form)

        btn = QPushButton("Create PKCS#12 Bundle")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_pkcs12)
        l.addWidget(btn)

        self._p12_status = self.build_status_label()
        l.addWidget(self._p12_status)
        _, self._p12_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_pkcs12(self):
        cert = self._p12_cert.text().strip()
        key = self._p12_key.text().strip()
        out = self._p12_out.text().strip()
        pwd = self._p12_pass.text()
        name = self._p12_name.text().strip() or "sslOpenCrypt"
        if not all([cert, key, out, pwd]):
            return
        self.run_in_thread(create_pkcs12, cert, key, out, pwd, None, name, callback=self._on_p12_done)

    def _on_p12_done(self, r):
        self.show_result(r, self._p12_output, self._p12_status)

    # ------------------------------------------------------------------
    # TLS Inspector
    # ------------------------------------------------------------------

    def _build_tls_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._tls_host = QLineEdit(); self._tls_host.setPlaceholderText("example.com")
        form.addRow("Hostname:", self._tls_host)
        self._tls_port = QSpinBox(); self._tls_port.setRange(1, 65535); self._tls_port.setValue(443)
        form.addRow("Port:", self._tls_port)
        l.addLayout(form)

        btn = QPushButton("Inspect TLS Certificate Chain")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_tls)
        l.addWidget(btn)

        self._tls_status = self.build_status_label()
        l.addWidget(self._tls_status)
        _, self._tls_output = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_tls(self):
        host = self._tls_host.text().strip()
        port = self._tls_port.value()
        if not host:
            return
        self._tls_status.setText("Connecting…")
        self._tls_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(inspect_tls, host, port, callback=self._on_tls_done)

    def _on_tls_done(self, r):
        self.show_result(r, self._tls_output, self._tls_status)
        if r.parsed:
            info = f"Host: {r.parsed.get('host')}:{r.parsed.get('port')}\n"
            info += f"Protocol: {r.parsed.get('protocol', 'unknown')}\n"
            info += f"Cipher: {r.parsed.get('cipher', 'unknown')}\n\n"
            subjects = r.parsed.get("subjects", [])
            if subjects:
                info += "Certificate chain subjects:\n" + "\n".join(f"  {s}" for s in subjects)
            self._tls_output.setPlainText(info + "\n\n" + r.stdout[:3000])
