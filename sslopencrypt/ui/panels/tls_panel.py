"""
ui/panels/tls_panel.py — Module 8: TLS Configuration Advisor panel.
"""

from PyQt6.QtWidgets import (
    QComboBox, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget,
)

from modules.tls.controller import (
    inspect_remote, build_config, rate_config,
    MOZILLA_INTERMEDIATE, MOZILLA_MODERN,
)
from .base_panel import BasePanel


class TLSPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🌐  TLS Configuration Advisor")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_inspector_tab(), "Remote Inspector")
        tabs.addTab(self._build_config_tab(), "Config Generator")
        tabs.addTab(self._build_rater_tab(), "Config Rater")
        layout.addWidget(tabs, stretch=1)

    def _build_inspector_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._ti_host = QLineEdit(); self._ti_host.setPlaceholderText("example.com")
        form.addRow("Hostname:", self._ti_host)
        self._ti_port = QSpinBox(); self._ti_port.setRange(1, 65535); self._ti_port.setValue(443)
        form.addRow("Port:", self._ti_port)
        self._ti_starttls = QComboBox()
        self._ti_starttls.addItems(["None", "smtp", "imap", "ftp"])
        form.addRow("STARTTLS:", self._ti_starttls)
        l.addLayout(form)

        btn = QPushButton("Inspect TLS")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_inspect)
        l.addWidget(btn)

        self._ti_status = self.build_status_label()
        l.addWidget(self._ti_status)
        _, self._ti_out = self.build_output_area("TLS Details")
        l.addWidget(_, stretch=1)
        return w

    def _do_inspect(self):
        host = self._ti_host.text().strip()
        if not host:
            return
        port = self._ti_port.value()
        starttls_val = self._ti_starttls.currentText()
        starttls = None if starttls_val == "None" else starttls_val
        self._ti_status.setText("Connecting…")
        self._ti_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(inspect_remote, host, port, starttls, callback=self._on_inspect_done)

    def _on_inspect_done(self, r):
        self.show_result(r, self._ti_out, self._ti_status)
        if r.parsed:
            info = (
                f"Host:     {r.parsed.get('host')}:{r.parsed.get('port')}\n"
                f"Protocol: {r.parsed.get('protocol', 'unknown')}\n"
                f"Cipher:   {r.parsed.get('cipher', 'unknown')}\n"
                f"Key bits: {r.parsed.get('server_key_bits', 'unknown')}\n\n"
                "Certificate chain subjects:\n"
            )
            for s in r.parsed.get("subjects", []):
                info += f"  {s}\n"
            self._ti_out.setPlainText(info + "\n" + r.stdout[:4000])

    def _build_config_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._cfg_server = QComboBox()
        self._cfg_server.addItems(["nginx", "apache", "haproxy", "postfix"])
        form.addRow("Server:", self._cfg_server)

        self._cfg_profile = QComboBox()
        self._cfg_profile.addItems(["intermediate", "modern"])
        form.addRow("Security Profile:", self._cfg_profile)
        l.addLayout(form)

        btn = QPushButton("Generate Configuration")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_config)
        l.addWidget(btn)

        profile_desc = {
            "intermediate": "Intermediate: TLS 1.2 + 1.3, ECDHE+DHE ciphers. Recommended for most services.",
            "modern": "Modern: TLS 1.3 only. Maximum security for modern clients.",
        }
        self._cfg_desc = QLabel(profile_desc["intermediate"])
        self._cfg_desc.setWordWrap(True)
        self._cfg_desc.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        self._cfg_profile.currentTextChanged.connect(lambda t: self._cfg_desc.setText(profile_desc.get(t, "")))
        l.addWidget(self._cfg_desc)

        _, self._cfg_out = self.build_output_area("Configuration Snippet")
        l.addWidget(_, stretch=1)
        return w

    def _do_config(self):
        server = self._cfg_server.currentText()
        profile = self._cfg_profile.currentText()
        config = build_config(server, profile)
        self._cfg_out.setPlainText(config)

    def _build_rater_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        info = QLabel("Rate a TLS configuration against Mozilla security profiles.")
        info.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        l.addWidget(info)

        form = QFormLayout()
        self._rate_vers = QLineEdit()
        self._rate_vers.setText("TLSv1.2, TLSv1.3")
        self._rate_vers.setPlaceholderText("TLSv1.2, TLSv1.3")
        form.addRow("TLS Versions:", self._rate_vers)

        self._rate_ciphers = QLineEdit()
        self._rate_ciphers.setPlaceholderText("ECDHE-RSA-AES256-GCM-SHA384:…")
        form.addRow("Cipher Suite:", self._rate_ciphers)
        l.addLayout(form)

        btn = QPushButton("Rate Configuration")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_rate)
        l.addWidget(btn)

        self._rate_grade = QLabel()
        self._rate_grade.setStyleSheet("font-size: 40px; font-weight: bold;")
        l.addWidget(self._rate_grade)

        _, self._rate_out = self.build_output_area("Analysis")
        l.addWidget(_, stretch=1)
        return w

    def _do_rate(self):
        versions_text = self._rate_vers.text()
        versions = [v.strip() for v in versions_text.split(",") if v.strip()]
        ciphers = self._rate_ciphers.text().strip()
        result = rate_config(versions, ciphers)

        grade = result["grade"]
        grade_colors = {"A+": "#10B981", "A": "#34D399", "B": "#F59E0B", "C": "#F97316", "F": "#EF4444"}
        color = grade_colors.get(grade, "#9CA3AF")
        self._rate_grade.setText(grade)
        self._rate_grade.setStyleSheet(f"font-size: 40px; font-weight: bold; color: {color};")

        text = f"Grade: {grade}  (Score: {result['score']}/100)\n"
        text += f"Mozilla Profile: {result['mozilla_profile']}\n\n"
        if result["issues"]:
            text += "Issues:\n" + "\n".join(f"  ✗ {i}" for i in result["issues"]) + "\n\n"
        if result["recommendations"]:
            text += "Recommendations:\n" + "\n".join(f"  → {r}" for r in result["recommendations"])
        self._rate_out.setPlainText(text)
