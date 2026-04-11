"""
ui/panels/hashing_panel.py — Module 3: Hashing & Digests panel.
"""

from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTabWidget, QTextEdit,
    QVBoxLayout, QWidget,
)

from modules.hashing.controller import (
    ALL_ALGORITHMS, BEGINNER_ALGORITHMS,
    hash_file, hash_text, hmac_text, verify_hash, avalanche_demo,
)
from .base_panel import BasePanel


class HashingPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._expert = False
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🔢  Hashing & Message Digests")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_hash_tab(), "Hash File")
        tabs.addTab(self._build_text_tab(), "Hash Text")
        tabs.addTab(self._build_hmac_tab(), "HMAC")
        tabs.addTab(self._build_verify_tab(), "Verify")
        tabs.addTab(self._build_avalanche_tab(), "Avalanche Demo")
        layout.addWidget(tabs, stretch=1)

    def _alg_combo(self) -> QComboBox:
        c = QComboBox()
        c.addItems(BEGINNER_ALGORITHMS if not self._expert else ALL_ALGORITHMS)
        return c

    # ------------------------------------------------------------------
    def _build_hash_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._hf_path = QLineEdit()
        self._hf_path.setPlaceholderText("Path to file")
        btn = QPushButton("Browse…")
        btn.setMaximumWidth(80)
        btn.clicked.connect(lambda: self._browse(self._hf_path))
        row = QHBoxLayout()
        row.addWidget(self._hf_path)
        row.addWidget(btn)
        form.addRow("File:", row)

        self._hf_alg = QComboBox()
        self._hf_alg.addItems(BEGINNER_ALGORITHMS)
        form.addRow("Algorithm:", self._hf_alg)
        l.addLayout(form)

        run_btn = QPushButton("Compute Hash")
        run_btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        run_btn.clicked.connect(self._do_hash_file)
        l.addWidget(run_btn)

        self._hf_status = self.build_status_label()
        l.addWidget(self._hf_status)
        _, self._hf_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _browse(self, edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if path:
            edit.setText(path)

    def _do_hash_file(self):
        path = self._hf_path.text().strip()
        alg = self._hf_alg.currentText()
        if not path:
            return
        self.run_in_thread(hash_file, path, alg, callback=self._on_hash_file_done)

    def _on_hash_file_done(self, r):
        self.show_result(r, self._hf_out, self._hf_status)
        if r.success and r.parsed.get("hash"):
            self._hf_out.setPlainText(
                f"Algorithm: {r.parsed['algorithm']}\nFile: {r.parsed['file']}\n\nHash:\n{r.parsed['hash']}"
            )

    # ------------------------------------------------------------------
    def _build_text_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._ht_text = QTextEdit()
        self._ht_text.setPlaceholderText("Enter text to hash…")
        self._ht_text.setMaximumHeight(80)
        form.addRow("Text:", self._ht_text)

        self._ht_alg = QComboBox()
        self._ht_alg.addItems(BEGINNER_ALGORITHMS)
        form.addRow("Algorithm:", self._ht_alg)
        l.addLayout(form)

        run_btn = QPushButton("Compute Hash")
        run_btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        run_btn.clicked.connect(self._do_hash_text)
        l.addWidget(run_btn)

        self._ht_status = self.build_status_label()
        l.addWidget(self._ht_status)
        _, self._ht_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_hash_text(self):
        text = self._ht_text.toPlainText()
        alg = self._ht_alg.currentText()
        if not text:
            return
        self.run_in_thread(hash_text, text, alg, callback=self._on_hash_text_done)

    def _on_hash_text_done(self, r):
        self.show_result(r, self._ht_out, self._ht_status)
        if r.success and r.parsed.get("hash"):
            self._ht_out.setPlainText(
                f"Algorithm: {r.parsed['algorithm']}\n\nHash:\n{r.parsed['hash']}"
            )

    # ------------------------------------------------------------------
    def _build_hmac_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._hm_text = QTextEdit()
        self._hm_text.setPlaceholderText("Enter message…")
        self._hm_text.setMaximumHeight(80)
        form.addRow("Message:", self._hm_text)

        self._hm_key = QLineEdit()
        self._hm_key.setPlaceholderText("HMAC key (secret)")
        form.addRow("Key:", self._hm_key)

        self._hm_alg = QComboBox()
        self._hm_alg.addItems(BEGINNER_ALGORITHMS)
        form.addRow("Algorithm:", self._hm_alg)
        l.addLayout(form)

        run_btn = QPushButton("Compute HMAC")
        run_btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        run_btn.clicked.connect(self._do_hmac)
        l.addWidget(run_btn)

        self._hm_status = self.build_status_label()
        l.addWidget(self._hm_status)
        _, self._hm_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_hmac(self):
        text = self._hm_text.toPlainText()
        key = self._hm_key.text()
        alg = self._hm_alg.currentText()
        if not text or not key:
            return
        self.run_in_thread(hmac_text, text, key, alg, callback=self._on_hmac_done)

    def _on_hmac_done(self, r):
        self.show_result(r, self._hm_out, self._hm_status)
        if r.success:
            self._hm_out.setPlainText(f"HMAC ({r.parsed.get('algorithm','')}):\n{r.parsed.get('hmac','')}")

    # ------------------------------------------------------------------
    def _build_verify_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        form = QFormLayout()
        self._vf_path = QLineEdit()
        self._vf_path.setPlaceholderText("File to verify")
        btn = QPushButton("Browse…")
        btn.setMaximumWidth(80)
        btn.clicked.connect(lambda: self._browse(self._vf_path))
        row = QHBoxLayout()
        row.addWidget(self._vf_path)
        row.addWidget(btn)
        form.addRow("File:", row)

        self._vf_ref = QLineEdit()
        self._vf_ref.setPlaceholderText("Expected hash (hex)")
        form.addRow("Expected hash:", self._vf_ref)

        self._vf_alg = QComboBox()
        self._vf_alg.addItems(BEGINNER_ALGORITHMS)
        form.addRow("Algorithm:", self._vf_alg)
        l.addLayout(form)

        run_btn = QPushButton("Verify")
        run_btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        run_btn.clicked.connect(self._do_verify)
        l.addWidget(run_btn)

        self._vf_status = self.build_status_label()
        l.addWidget(self._vf_status)
        _, self._vf_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_verify(self):
        path = self._vf_path.text().strip()
        ref = self._vf_ref.text().strip()
        alg = self._vf_alg.currentText()
        if not path or not ref:
            return
        self.run_in_thread(verify_hash, path, ref, alg, callback=self._on_verify_done)

    def _on_verify_done(self, r):
        match = r.parsed.get("match")
        computed = r.parsed.get("computed_hash", "")
        reference = r.parsed.get("reference_hash", "")
        if match is True:
            self._vf_status.setText("✓  MATCH — File integrity verified")
            self._vf_status.setStyleSheet("color: #34D399; font-weight: bold; font-size: 12px;")
        elif match is False:
            self._vf_status.setText("✗  MISMATCH — File may be corrupted or tampered")
            self._vf_status.setStyleSheet("color: #F87171; font-weight: bold; font-size: 12px;")
        else:
            self._vf_status.setText(f"Error: {r.error_message}")
            self._vf_status.setStyleSheet("color: #F87171;")
        self._vf_out.setPlainText(
            f"Computed:  {computed}\nExpected:  {reference}\nMatch: {match}"
        )

    # ------------------------------------------------------------------
    def _build_avalanche_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setSpacing(8)

        info = QLabel(
            "Avalanche Effect Demo: change one character in the input and observe how "
            "the hash completely changes. This demonstrates the sensitivity of cryptographic hash functions."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        l.addWidget(info)

        form = QFormLayout()
        self._av_text = QLineEdit()
        self._av_text.setPlaceholderText("Enter any text…")
        form.addRow("Input:", self._av_text)

        self._av_alg = QComboBox()
        self._av_alg.addItems(BEGINNER_ALGORITHMS)
        form.addRow("Algorithm:", self._av_alg)
        l.addLayout(form)

        run_btn = QPushButton("Show Avalanche Effect")
        run_btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        run_btn.clicked.connect(self._do_avalanche)
        l.addWidget(run_btn)

        _, self._av_out = self.build_output_area()
        l.addWidget(_, stretch=1)
        return w

    def _do_avalanche(self):
        text = self._av_text.text()
        alg = self._av_alg.currentText()
        if not text:
            return
        import threading
        result = avalanche_demo(text, alg)
        if result:
            self._av_out.setPlainText(
                f"Original text:  \"{result['original_text']}\"\n"
                f"Modified text:  \"{result['modified_text']}\" (first char XOR'd by 1)\n\n"
                f"Original hash ({alg}):\n  {result['original_hash']}\n\n"
                f"Modified hash ({alg}):\n  {result['modified_hash']}\n\n"
                f"Bits changed: {result['bits_changed']} / {result['total_bits']} "
                f"({result['percent_changed']}%)\n\n"
                "A single character change flips ~50% of the output bits — the avalanche effect."
            )

    def set_expert_mode(self, expert: bool):
        self._expert = expert
        for combo in [self._hf_alg, self._ht_alg, self._hm_alg, self._vf_alg, self._av_alg]:
            combo.clear()
            combo.addItems(ALL_ALGORITHMS if expert else BEGINNER_ALGORITHMS)
