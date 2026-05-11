"""
ui/panels/tangodos_panel.py — Sibling support for TangoDOS automation panels.

Wizard tabs:
  1. HTTPS cert     — produces HTTP_CRT.PEM + HTTP_KEY.PEM for one panel
  2. MQTT mTLS      — produces MQTT_CA.PEM + MQTT_CLIENT_*.PEM bundle
  3. Fleet CA       — root CA for an org running many panels
  4. Firmware sign  — EC P-256 key generation + .sig / .signed production
  5. Self-test      — verify a panel-emitted self-test report's signature
  6. TLS inspector  — point at https://panel.local, see what cert it serves
  7. PKCS#12        — bundle a panel's cert + key into one .p12

The TangoDOS firmware reads HTTP_CRT.PEM / HTTP_KEY.PEM / MQTT_*.PEM directly
from LittleFS, so every output uses the canonical filenames a panel expects.
"""

from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QSpinBox, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from modules.tangodos.controller import (
    DEFAULT_PANEL_CERT_DAYS, DEFAULT_FLEET_CA_DAYS,
    HTTPS_CERT_FILENAME, HTTPS_KEY_FILENAME,
    MQTT_CA_FILENAME, MQTT_CLIENT_CERT_FILENAME, MQTT_CLIENT_KEY_FILENAME,
    generate_panel_https_cert,
    generate_mqtt_mtls_bundle,
    generate_fleet_ca,
    generate_firmware_signing_key,
    sign_firmware,
    verify_firmware_signature,
    verify_self_test_report,
    inspect_self_test_report,
    inspect_panel_tls,
    export_panel_pkcs12,
    panel_file_layout,
)
from .base_panel import BasePanel


_TITLE_STYLE = "font-size: 18px; font-weight: bold; color: #F9FAFB;"
_HINT_STYLE  = "color: #9CA3AF; font-size: 10px;"
_RUN_BUTTON_STYLE = "background:#1D4ED8; color:white; padding:8px; border-radius:6px; font-weight:bold;"


class TangoDOSPanel(BasePanel):
    """sslOpenCrypt panel that produces the cryptographic material a TangoDOS
    automation panel consumes. Sibling-project pattern: file-format boundary,
    no shared compiled code."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🛠  TangoDOS — automation-panel crypto support")
        title.setStyleSheet(_TITLE_STYLE)
        layout.addWidget(title)

        intro = QLabel(
            "TangoDOS panels (Pi Pico 2 W / Pimoroni Pico Plus 2 W) read their "
            "certificates and keys from LittleFS at well-known filenames. Each "
            "tab below produces those files ready to drop onto the panel's "
            "dashboard. No TangoDOS source is touched — only its public file "
            "conventions."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(_HINT_STYLE)
        layout.addWidget(intro)

        layout_summary = QLabel(self._layout_summary_text())
        layout_summary.setStyleSheet(
            "background:#111827; color:#D1FAE5; border:1px solid #374151; "
            "border-radius:4px; padding:8px; font-family: monospace; font-size: 10px;"
        )
        layout.addWidget(layout_summary)

        tabs = QTabWidget()
        tabs.addTab(self._build_https_tab(),     "1. HTTPS cert")
        tabs.addTab(self._build_mqtt_tab(),      "2. MQTT mTLS")
        tabs.addTab(self._build_ca_tab(),        "3. Fleet CA")
        tabs.addTab(self._build_firmware_tab(),  "4. Firmware signing")
        tabs.addTab(self._build_selftest_tab(),  "5. Self-test report")
        tabs.addTab(self._build_tls_tab(),       "6. TLS inspector")
        tabs.addTab(self._build_p12_tab(),       "7. PKCS#12 export")
        layout.addWidget(tabs, stretch=1)

    # ------------------------------------------------------------------
    # File-name reminder banner
    # ------------------------------------------------------------------
    @staticmethod
    def _layout_summary_text() -> str:
        layout = panel_file_layout()
        widest = max(len(k) for k in layout)
        rows = [f"{k.ljust(widest)}  →  /{v}" for k, v in layout.items()]
        return "TangoDOS file conventions (LittleFS root):\n" + "\n".join(rows)

    # ------------------------------------------------------------------
    # Generic helpers — file pickers, output area
    # ------------------------------------------------------------------
    def _file_picker_row(self, edit: QLineEdit, mode: str = "open",
                         filt: str = "All Files (*)") -> QHBoxLayout:
        btn = QPushButton("Browse…")
        btn.setMaximumWidth(80)
        def _click():
            if mode == "open":
                p, _ = QFileDialog.getOpenFileName(self, "Select file", "", filt)
            elif mode == "save":
                p, _ = QFileDialog.getSaveFileName(self, "Save as", edit.text() or "", filt)
            elif mode == "dir":
                p = QFileDialog.getExistingDirectory(self, "Select folder", edit.text() or "")
            else:
                p = ""
            if p:
                edit.setText(p)
        btn.clicked.connect(_click)
        row = QHBoxLayout()
        row.addWidget(edit)
        row.addWidget(btn)
        return row

    def _attach_output(self, parent_layout: QVBoxLayout):
        status = self.build_status_label()
        parent_layout.addWidget(status)
        _, output = self.build_output_area()
        parent_layout.addWidget(_, stretch=1)
        return status, output

    # ==================================================================
    # 1. HTTPS cert
    # ==================================================================
    def _build_https_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "Produces a self-signed HTTPS server certificate + key for ONE panel. "
            "Upload both files via the panel's dashboard at <code>/dashboard/upload</code>; "
            f"they MUST be saved as <code>/{HTTPS_CERT_FILENAME}</code> and "
            f"<code>/{HTTPS_KEY_FILENAME}</code> in LittleFS. Restart the panel to load."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        form = QFormLayout()
        self._https_cn = QLineEdit()
        self._https_cn.setPlaceholderText("panel-brewery-01.local")
        form.addRow("Panel hostname (CN):", self._https_cn)

        self._https_sans = QLineEdit()
        self._https_sans.setPlaceholderText("optional, comma-separated: 10.0.0.42, panel-brewery-01")
        form.addRow("Extra SANs:", self._https_sans)

        self._https_org = QLineEdit("TangoDOS Panel")
        form.addRow("Organisation:", self._https_org)

        self._https_days = QSpinBox()
        self._https_days.setRange(30, 3650)
        self._https_days.setValue(DEFAULT_PANEL_CERT_DAYS)
        form.addRow("Validity (days):", self._https_days)

        self._https_outdir = QLineEdit()
        self._https_outdir.setPlaceholderText("Folder to write HTTP_CRT.PEM + HTTP_KEY.PEM")
        form.addRow("Output folder:", self._file_picker_row(self._https_outdir, mode="dir"))
        l.addLayout(form)

        run = QPushButton("Generate HTTPS cert + key")
        run.setStyleSheet(_RUN_BUTTON_STYLE)
        run.clicked.connect(self._do_https)
        l.addWidget(run)

        self._https_status, self._https_output = self._attach_output(l)
        return w

    def _do_https(self):
        cn = self._https_cn.text().strip()
        outdir = self._https_outdir.text().strip()
        if not cn or not outdir:
            self._https_status.setText("✗  Enter a hostname and choose an output folder.")
            self._https_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        sans = [s.strip() for s in self._https_sans.text().split(",") if s.strip()]
        self.run_in_thread(
            generate_panel_https_cert,
            cn, outdir,
            sans=sans,
            days=self._https_days.value(),
            organisation=self._https_org.text().strip() or "TangoDOS Panel",
            callback=lambda r: self.show_result(r, self._https_output, self._https_status),
        )

    # ==================================================================
    # 2. MQTT mTLS
    # ==================================================================
    def _build_mqtt_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "Produces the three files the panel needs for MQTT mTLS: the broker's "
            f"CA (<code>/{MQTT_CA_FILENAME}</code>), this panel's client cert "
            f"(<code>/{MQTT_CLIENT_CERT_FILENAME}</code>) and key "
            f"(<code>/{MQTT_CLIENT_KEY_FILENAME}</code>). If you provide a "
            "signing CA cert+key (e.g. your fleet CA from tab 3), the client cert "
            "is CA-signed; otherwise self-signed."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        form = QFormLayout()
        self._mqtt_broker_ca = QLineEdit()
        self._mqtt_broker_ca.setPlaceholderText("path to broker's CA PEM")
        form.addRow("Broker CA:", self._file_picker_row(self._mqtt_broker_ca, mode="open", filt="PEM (*.pem *.crt);;All Files (*)"))

        self._mqtt_device_cn = QLineEdit()
        self._mqtt_device_cn.setPlaceholderText("device CN, e.g. panel-brewery-01")
        form.addRow("Device CN:", self._mqtt_device_cn)

        self._mqtt_sign_cert = QLineEdit()
        self._mqtt_sign_cert.setPlaceholderText("optional: fleet CA cert")
        form.addRow("Signing CA cert:", self._file_picker_row(self._mqtt_sign_cert, mode="open", filt="PEM (*.pem *.crt);;All Files (*)"))

        self._mqtt_sign_key = QLineEdit()
        self._mqtt_sign_key.setPlaceholderText("optional: fleet CA key")
        form.addRow("Signing CA key:", self._file_picker_row(self._mqtt_sign_key, mode="open", filt="PEM (*.pem *.key);;All Files (*)"))

        self._mqtt_days = QSpinBox()
        self._mqtt_days.setRange(30, 3650)
        self._mqtt_days.setValue(DEFAULT_PANEL_CERT_DAYS)
        form.addRow("Validity (days):", self._mqtt_days)

        self._mqtt_outdir = QLineEdit()
        self._mqtt_outdir.setPlaceholderText("Folder to write the MQTT bundle")
        form.addRow("Output folder:", self._file_picker_row(self._mqtt_outdir, mode="dir"))
        l.addLayout(form)

        run = QPushButton("Generate MQTT mTLS bundle")
        run.setStyleSheet(_RUN_BUTTON_STYLE)
        run.clicked.connect(self._do_mqtt)
        l.addWidget(run)

        self._mqtt_status, self._mqtt_output = self._attach_output(l)
        return w

    def _do_mqtt(self):
        broker_ca = self._mqtt_broker_ca.text().strip()
        device_cn = self._mqtt_device_cn.text().strip()
        outdir    = self._mqtt_outdir.text().strip()
        if not broker_ca or not device_cn or not outdir:
            self._mqtt_status.setText("✗  Broker CA, device CN, and output folder are required.")
            self._mqtt_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        sign_cert = self._mqtt_sign_cert.text().strip() or None
        sign_key  = self._mqtt_sign_key.text().strip()  or None
        self.run_in_thread(
            generate_mqtt_mtls_bundle,
            broker_ca, device_cn, outdir,
            days=self._mqtt_days.value(),
            signing_ca_cert=sign_cert,
            signing_ca_key=sign_key,
            callback=lambda r: self.show_result(r, self._mqtt_output, self._mqtt_status),
        )

    # ==================================================================
    # 3. Fleet CA
    # ==================================================================
    def _build_ca_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "Builds a small in-house root CA. Distribute the CA cert to brokers "
            "(<code>cafile=...</code>) and operators' browsers; sign per-panel "
            "certificates with the CA key in tab 2. Keep the CA key offline."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        form = QFormLayout()
        self._ca_org = QLineEdit()
        self._ca_org.setPlaceholderText("e.g. Acme Brewery Co.")
        form.addRow("Organisation:", self._ca_org)

        self._ca_cn = QLineEdit("TangoDOS Fleet Root CA")
        form.addRow("Common Name:", self._ca_cn)

        self._ca_days = QSpinBox()
        self._ca_days.setRange(365, 7300)
        self._ca_days.setValue(DEFAULT_FLEET_CA_DAYS)
        form.addRow("Validity (days):", self._ca_days)

        self._ca_outdir = QLineEdit()
        self._ca_outdir.setPlaceholderText("Folder to write the CA cert + key")
        form.addRow("Output folder:", self._file_picker_row(self._ca_outdir, mode="dir"))
        l.addLayout(form)

        run = QPushButton("Generate fleet CA")
        run.setStyleSheet(_RUN_BUTTON_STYLE)
        run.clicked.connect(self._do_ca)
        l.addWidget(run)

        self._ca_status, self._ca_output = self._attach_output(l)
        return w

    def _do_ca(self):
        org = self._ca_org.text().strip()
        cn  = self._ca_cn.text().strip()
        outdir = self._ca_outdir.text().strip()
        if not org or not outdir:
            self._ca_status.setText("✗  Organisation and output folder are required.")
            self._ca_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        self.run_in_thread(
            generate_fleet_ca,
            org, cn or "TangoDOS Fleet Root CA", outdir,
            days=self._ca_days.value(),
            callback=lambda r: self.show_result(r, self._ca_output, self._ca_status),
        )

    # ==================================================================
    # 4. Firmware signing
    # ==================================================================
    def _build_firmware_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "EC P-256 firmware signing. First generate a signing keypair (once), "
            "then use it to sign each release .bin / .uf2. The panel verifies the "
            "detached .sig against the matching public key on first boot."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        # — keygen sub-section —
        kg_label = QLabel("Generate a new firmware signing key")
        kg_label.setStyleSheet("font-weight:bold;")
        l.addWidget(kg_label)

        kg_form = QFormLayout()
        self._fw_keyout = QLineEdit()
        self._fw_keyout.setPlaceholderText("path for the new private key PEM")
        kg_form.addRow("Output:", self._file_picker_row(self._fw_keyout, mode="save", filt="PEM (*.pem)"))
        l.addLayout(kg_form)

        kg_btn = QPushButton("Generate signing keypair")
        kg_btn.setStyleSheet(_RUN_BUTTON_STYLE)
        kg_btn.clicked.connect(self._do_fw_keygen)
        l.addWidget(kg_btn)

        # — signing sub-section —
        sign_label = QLabel("Sign a firmware image")
        sign_label.setStyleSheet("font-weight:bold; margin-top: 8px;")
        l.addWidget(sign_label)

        sn_form = QFormLayout()
        self._fw_blob = QLineEdit()
        self._fw_blob.setPlaceholderText("path to the firmware .bin / .uf2")
        sn_form.addRow("Firmware:", self._file_picker_row(self._fw_blob, mode="open", filt="Firmware (*.bin *.uf2);;All Files (*)"))

        self._fw_signkey = QLineEdit()
        self._fw_signkey.setPlaceholderText("path to your signing key PEM")
        sn_form.addRow("Signing key:", self._file_picker_row(self._fw_signkey, mode="open", filt="PEM (*.pem)"))

        self._fw_outdir = QLineEdit()
        self._fw_outdir.setPlaceholderText("Folder for .sig / .signed (defaults to firmware folder)")
        sn_form.addRow("Output folder:", self._file_picker_row(self._fw_outdir, mode="dir"))
        l.addLayout(sn_form)

        sign_btn = QPushButton("Sign firmware")
        sign_btn.setStyleSheet(_RUN_BUTTON_STYLE)
        sign_btn.clicked.connect(self._do_fw_sign)
        l.addWidget(sign_btn)

        # — verify sub-section —
        ver_label = QLabel("Verify a firmware signature")
        ver_label.setStyleSheet("font-weight:bold; margin-top: 8px;")
        l.addWidget(ver_label)

        v_form = QFormLayout()
        self._fw_v_blob = QLineEdit()
        v_form.addRow("Firmware:", self._file_picker_row(self._fw_v_blob, mode="open", filt="Firmware (*.bin *.uf2);;All Files (*)"))
        self._fw_v_sig = QLineEdit()
        v_form.addRow("Signature:", self._file_picker_row(self._fw_v_sig, mode="open", filt="Signature (*.sig);;All Files (*)"))
        self._fw_v_pub = QLineEdit()
        v_form.addRow("Public key:", self._file_picker_row(self._fw_v_pub, mode="open", filt="PEM (*.pem)"))
        l.addLayout(v_form)

        ver_btn = QPushButton("Verify signature")
        ver_btn.setStyleSheet(_RUN_BUTTON_STYLE)
        ver_btn.clicked.connect(self._do_fw_verify)
        l.addWidget(ver_btn)

        self._fw_status, self._fw_output = self._attach_output(l)
        return w

    def _do_fw_keygen(self):
        path = self._fw_keyout.text().strip()
        if not path:
            self._fw_status.setText("✗  Choose an output path for the new key.")
            self._fw_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        self.run_in_thread(
            generate_firmware_signing_key, path,
            callback=lambda r: self.show_result(r, self._fw_output, self._fw_status),
        )

    def _do_fw_sign(self):
        fw = self._fw_blob.text().strip()
        key = self._fw_signkey.text().strip()
        outdir = self._fw_outdir.text().strip() or None
        if not fw or not key:
            self._fw_status.setText("✗  Firmware and signing key paths are required.")
            self._fw_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        self.run_in_thread(
            sign_firmware, fw, key, outdir,
            callback=lambda r: self.show_result(r, self._fw_output, self._fw_status),
        )

    def _do_fw_verify(self):
        fw  = self._fw_v_blob.text().strip()
        sig = self._fw_v_sig.text().strip()
        pub = self._fw_v_pub.text().strip()
        if not fw or not sig or not pub:
            self._fw_status.setText("✗  Firmware, signature, and public key are all required.")
            self._fw_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        self.run_in_thread(
            verify_firmware_signature, fw, sig, pub,
            callback=lambda r: self.show_result(r, self._fw_output, self._fw_status),
        )

    # ==================================================================
    # 5. Self-test report
    # ==================================================================
    def _build_selftest_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "Verify a self-test report exported from a TangoDOS panel "
            "(Diagnostics → Export self-test report). Verifying the signature "
            "confirms the report came from a panel signed with the matching "
            "firmware-signing key. Inspecting (without a signature) just parses "
            "the JSON and shows a summary."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        form = QFormLayout()
        self._st_report = QLineEdit()
        form.addRow("Report (JSON):", self._file_picker_row(self._st_report, mode="open", filt="JSON (*.json);;All Files (*)"))
        self._st_sig = QLineEdit()
        form.addRow("Signature:", self._file_picker_row(self._st_sig, mode="open", filt="Signature (*.sig);;All Files (*)"))
        self._st_pub = QLineEdit()
        form.addRow("Public key:", self._file_picker_row(self._st_pub, mode="open", filt="PEM (*.pem)"))
        l.addLayout(form)

        row = QHBoxLayout()
        b_inspect = QPushButton("Inspect (no signature)")
        b_inspect.setStyleSheet(_RUN_BUTTON_STYLE)
        b_inspect.clicked.connect(self._do_st_inspect)
        row.addWidget(b_inspect)

        b_verify = QPushButton("Verify signature")
        b_verify.setStyleSheet(_RUN_BUTTON_STYLE)
        b_verify.clicked.connect(self._do_st_verify)
        row.addWidget(b_verify)
        l.addLayout(row)

        self._st_status, self._st_output = self._attach_output(l)
        return w

    def _do_st_inspect(self):
        path = self._st_report.text().strip()
        if not path:
            return
        self.run_in_thread(
            inspect_self_test_report, path,
            callback=lambda r: self.show_result(r, self._st_output, self._st_status),
        )

    def _do_st_verify(self):
        rp  = self._st_report.text().strip()
        sig = self._st_sig.text().strip()
        pub = self._st_pub.text().strip()
        if not rp or not sig or not pub:
            self._st_status.setText("✗  Report, signature, and public key are required.")
            self._st_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        self.run_in_thread(
            verify_self_test_report, rp, sig, pub,
            callback=lambda r: self.show_result(r, self._st_output, self._st_status),
        )

    # ==================================================================
    # 6. TLS inspector
    # ==================================================================
    def _build_tls_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "Connect to a running TangoDOS panel over TLS and print its cert "
            "chain + cipher. Useful to confirm whether a panel is serving its "
            "per-device cert or the shipped placeholder."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        form = QFormLayout()
        self._tls_host = QLineEdit()
        self._tls_host.setPlaceholderText("panel-brewery-01.local")
        form.addRow("Host:", self._tls_host)
        self._tls_port = QSpinBox()
        self._tls_port.setRange(1, 65535)
        self._tls_port.setValue(443)
        form.addRow("Port:", self._tls_port)
        l.addLayout(form)

        run = QPushButton("Inspect TLS")
        run.setStyleSheet(_RUN_BUTTON_STYLE)
        run.clicked.connect(self._do_tls)
        l.addWidget(run)

        self._tls_status, self._tls_output = self._attach_output(l)
        return w

    def _do_tls(self):
        host = self._tls_host.text().strip()
        if not host:
            return
        self.run_in_thread(
            inspect_panel_tls, host, self._tls_port.value(),
            callback=lambda r: self.show_result(r, self._tls_output, self._tls_status),
        )

    # ==================================================================
    # 7. PKCS#12 export
    # ==================================================================
    def _build_p12_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)

        hint = QLabel(
            "Bundle a panel's cert + key (and optional CA chain) into a single "
            ".p12 file. The TangoDOS dashboard accepts .p12 uploads and splits "
            "them server-side — easier than uploading PEMs separately."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(_HINT_STYLE)
        l.addWidget(hint)

        form = QFormLayout()
        self._p12_cert = QLineEdit()
        form.addRow("Cert PEM:", self._file_picker_row(self._p12_cert, mode="open", filt="PEM (*.pem *.crt);;All Files (*)"))
        self._p12_key = QLineEdit()
        form.addRow("Key PEM:", self._file_picker_row(self._p12_key, mode="open", filt="PEM (*.pem *.key);;All Files (*)"))
        self._p12_ca = QLineEdit()
        form.addRow("CA chain (optional):", self._file_picker_row(self._p12_ca, mode="open", filt="PEM (*.pem *.crt);;All Files (*)"))
        self._p12_name = QLineEdit("TangoDOS panel")
        form.addRow("Friendly name:", self._p12_name)
        self._p12_pass = QLineEdit()
        self._p12_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._p12_pass.setPlaceholderText("passphrase to protect the .p12")
        form.addRow("Passphrase:", self._p12_pass)
        self._p12_out = QLineEdit()
        form.addRow("Output .p12:", self._file_picker_row(self._p12_out, mode="save", filt="PKCS#12 (*.p12)"))
        l.addLayout(form)

        run = QPushButton("Build PKCS#12")
        run.setStyleSheet(_RUN_BUTTON_STYLE)
        run.clicked.connect(self._do_p12)
        l.addWidget(run)

        self._p12_status, self._p12_output = self._attach_output(l)
        return w

    def _do_p12(self):
        cert = self._p12_cert.text().strip()
        key  = self._p12_key.text().strip()
        ca   = self._p12_ca.text().strip() or None
        out  = self._p12_out.text().strip()
        name = self._p12_name.text().strip() or "TangoDOS panel"
        pw   = self._p12_pass.text()
        if not cert or not key or not out or not pw:
            self._p12_status.setText("✗  Cert, key, output, and passphrase are required.")
            self._p12_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return
        self.run_in_thread(
            export_panel_pkcs12, cert, key, ca, out, name, pw,
            callback=lambda r: self.show_result(r, self._p12_output, self._p12_status),
        )
