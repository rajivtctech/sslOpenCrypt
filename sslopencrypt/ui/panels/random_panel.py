"""
ui/panels/random_panel.py — Module 7: Secure Random & Password Generator panel.
"""

from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSpinBox, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget,
)

from modules.random.controller import (
    random_bytes, random_password, random_uuid, random_prime, dhparam, entropy_estimate,
)
from .base_panel import BasePanel


class RandomPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🎲  Secure Random Number & Password Generator")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_bytes_tab(), "Random Bytes")
        tabs.addTab(self._build_password_tab(), "Password Generator")
        tabs.addTab(self._build_prime_tab(), "Prime / DH Params")
        layout.addWidget(tabs, stretch=1)

    def _build_bytes_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._rb_count = QSpinBox(); self._rb_count.setRange(1, 4096); self._rb_count.setValue(32)
        form.addRow("Byte count:", self._rb_count)

        self._rb_fmt = QComboBox(); self._rb_fmt.addItems(["hex", "base64"])
        form.addRow("Output format:", self._rb_fmt)
        l.addLayout(form)

        btn = QPushButton("Generate Random Bytes")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_bytes)
        l.addWidget(btn)

        self._rb_status = self.build_status_label()
        l.addWidget(self._rb_status)
        _, self._rb_out = self.build_output_area("Random Output")
        l.addWidget(_, stretch=1)

        self._entropy_label = QLabel()
        self._entropy_label.setStyleSheet("color: #6EE7B7; font-size: 10px;")
        l.addWidget(self._entropy_label)
        return w

    def _do_bytes(self):
        count = self._rb_count.value()
        fmt = self._rb_fmt.currentText()
        self.run_in_thread(random_bytes, count, fmt, callback=self._on_bytes_done)

    def _on_bytes_done(self, r):
        self.show_result(r, self._rb_out, self._rb_status)
        if r.success:
            val = r.parsed.get("value", r.stdout.strip())
            self._rb_out.setPlainText(val)
            bits = r.parsed.get("entropy_bits", 0)
            self._entropy_label.setText(f"Entropy: {bits} bits")
            if r.parsed.get("value"):
                est = entropy_estimate(r.parsed["value"])
                self._entropy_label.setText(
                    f"Entropy: {est.get('entropy_bits', bits)} bits  "
                    f"({est.get('charset', '')})"
                )

    def _build_password_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._pw_len = QSpinBox(); self._pw_len.setRange(8, 256); self._pw_len.setValue(20)
        form.addRow("Length:", self._pw_len)

        self._pw_upper = QCheckBox("Uppercase A-Z"); self._pw_upper.setChecked(True)
        self._pw_lower = QCheckBox("Lowercase a-z"); self._pw_lower.setChecked(True)
        self._pw_digits = QCheckBox("Digits 0-9"); self._pw_digits.setChecked(True)
        self._pw_symbols = QCheckBox("Symbols"); self._pw_symbols.setChecked(True)
        self._pw_no_ambig = QCheckBox("Exclude ambiguous (Il1O0)"); self._pw_no_ambig.setChecked(True)

        for cb in [self._pw_upper, self._pw_lower, self._pw_digits, self._pw_symbols, self._pw_no_ambig]:
            form.addRow("", cb)
        l.addLayout(form)

        btn = QPushButton("Generate Password")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_password)
        l.addWidget(btn)

        self._pw_status = self.build_status_label()
        l.addWidget(self._pw_status)
        _, self._pw_out = self.build_output_area("Generated Password")
        l.addWidget(_, stretch=1)
        return w

    def _do_password(self):
        self.run_in_thread(
            random_password,
            self._pw_len.value(),
            self._pw_upper.isChecked(),
            self._pw_lower.isChecked(),
            self._pw_digits.isChecked(),
            self._pw_symbols.isChecked(),
            self._pw_no_ambig.isChecked(),
            callback=self._on_password_done,
        )

    def _on_password_done(self, r):
        self.show_result(r, self._pw_out, self._pw_status)
        if r.success:
            pw = r.parsed.get("password", "")
            entropy = r.parsed.get("entropy_bits", 0)
            charset = r.parsed.get("charset_size", 0)
            self._pw_out.setPlainText(
                f"{pw}\n\n"
                f"Entropy: {entropy} bits  |  Charset size: {charset}  |  Length: {r.parsed.get('length', 0)}"
            )

    def _build_prime_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._prime_bits = QSpinBox(); self._prime_bits.setRange(64, 4096); self._prime_bits.setValue(512)
        form.addRow("Prime bits:", self._prime_bits)
        l.addLayout(form)

        btn_prime = QPushButton("Generate Random Prime")
        btn_prime.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn_prime.clicked.connect(self._do_prime)
        l.addWidget(btn_prime)

        sep = QLabel("── Diffie-Hellman Parameters ──")
        sep.setStyleSheet("color: #6B7280; font-size: 10px; margin-top: 12px;")
        l.addWidget(sep)

        dh_note = QLabel(
            "⚠  DH parameter generation can take several minutes for 2048-bit or larger."
        )
        dh_note.setWordWrap(True)
        dh_note.setStyleSheet("color: #FCD34D; font-size: 10px;")
        l.addWidget(dh_note)

        form2 = QFormLayout()
        self._dh_bits = QComboBox(); self._dh_bits.addItems(["1024", "2048", "4096"])
        self._dh_bits.setCurrentText("2048")
        form2.addRow("DH bits:", self._dh_bits)
        l.addLayout(form2)

        btn_dh = QPushButton("Generate DH Parameters (may take minutes…)")
        btn_dh.setStyleSheet("background:#7C3AED; color:white; padding:8px; border-radius:6px;")
        btn_dh.clicked.connect(self._do_dh)
        l.addWidget(btn_dh)

        self._prime_status = self.build_status_label()
        l.addWidget(self._prime_status)
        _, self._prime_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_prime(self):
        bits = self._prime_bits.value()
        self.run_in_thread(random_prime, bits, callback=self._on_prime_done)

    def _on_prime_done(self, r):
        self.show_result(r, self._prime_out, self._prime_status)
        if r.success:
            self._prime_out.setPlainText(f"Prime ({r.parsed.get('bits')} bits):\n{r.parsed.get('prime', r.stdout)}")

    def _do_dh(self):
        bits = int(self._dh_bits.currentText())
        self._prime_status.setText("Generating DH parameters… this can take several minutes.")
        self._prime_status.setStyleSheet("color: #60A5FA;")
        self.run_in_thread(dhparam, bits, callback=self._on_dh_done)

    def _on_dh_done(self, r):
        self.show_result(r, self._prime_out, self._prime_status)
