"""
ui/panels/keymgmt_panel.py — Module 1: Key Management panel.
"""

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox,
    QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget,
    QTextEdit, QVBoxLayout, QWidget, QSizePolicy,
)

from PyQt6.QtWidgets import QInputDialog


def _simple_input_dialog(parent, title: str, label: str, default: str = "") -> tuple[str, bool]:
    return QInputDialog.getText(parent, title, label, text=default)


from modules.keymgmt.controller import (
    ALL_ALGORITHMS, BEGINNER_ALGORITHMS,
    generate_key, inspect_key, extract_public_key, convert_key,
)
from core.result import ExecutionResult
from .base_panel import BasePanel


class KeyMgmtPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._expert = False
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🔑  Key Management")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB; margin-bottom: 8px;")
        layout.addWidget(title)

        desc = QLabel(
            "Generate, inspect, convert, and manage asymmetric key pairs.\n"
            "Supports RSA, ECDSA, Ed25519, Ed448, X25519, X448, and DSA."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(desc)

        tabs = QTabWidget()
        tabs.addTab(self._build_generate_tab(), "Generate")
        tabs.addTab(self._build_inspect_tab(), "Inspect")
        tabs.addTab(self._build_extract_tab(), "Extract Public Key")
        tabs.addTab(self._build_convert_tab(), "Convert")
        layout.addWidget(tabs, stretch=1)

    # ------------------------------------------------------------------
    # Generate tab
    # ------------------------------------------------------------------

    def _build_generate_tab(self) -> QWidget:
        w = QWidget()
        main = QVBoxLayout(w)
        main.setSpacing(10)

        form = QFormLayout()
        form.setSpacing(8)

        self._alg_combo = QComboBox()
        self._alg_combo.addItems(BEGINNER_ALGORITHMS)
        self._alg_combo.setToolTip("Select key algorithm and size")
        form.addRow("Algorithm:", self._alg_combo)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Optional — leave blank for unprotected key")
        self._pass_edit.setToolTip(
            "If set, the private key will be encrypted with AES-256-CBC.\n"
            "You will need this passphrase to use the key."
        )
        form.addRow("Passphrase:", self._pass_edit)

        self._pass_confirm = QLineEdit()
        self._pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_confirm.setPlaceholderText("Confirm passphrase")
        form.addRow("Confirm:", self._pass_confirm)

        self._out_edit = QLineEdit()
        self._out_edit.setPlaceholderText("/home/user/private_key.pem")
        btn_browse = QPushButton("Browse…")
        btn_browse.setMaximumWidth(80)
        btn_browse.clicked.connect(self._browse_output)
        out_row = QHBoxLayout()
        out_row.addWidget(self._out_edit)
        out_row.addWidget(btn_browse)
        form.addRow("Private key output:", out_row)

        main.addLayout(form)

        # Button row
        btn_row = QHBoxLayout()
        self._btn_generate = QPushButton("Generate Key Pair")
        self._btn_generate.setStyleSheet(
            "background:#1D4ED8; color:white; font-weight:bold; padding:8px; border-radius:6px;"
        )
        self._btn_generate.clicked.connect(self._do_generate)
        btn_row.addWidget(self._btn_generate)

        self._btn_save_vault = QPushButton("💾  Save to Vault")
        self._btn_save_vault.setStyleSheet(
            "background:#374151; color:#9CA3AF; padding:8px; border-radius:6px;"
        )
        self._btn_save_vault.setEnabled(False)
        self._btn_save_vault.setToolTip("Save generated private key to the encrypted Key Vault")
        self._btn_save_vault.clicked.connect(self._do_save_to_vault)
        btn_row.addWidget(self._btn_save_vault)
        btn_row.addStretch()
        main.addLayout(btn_row)

        # Status
        self._gen_status = self.build_status_label()
        main.addWidget(self._gen_status)

        # Output
        _, self._gen_output = self.build_output_area("Result")
        main.addWidget(_, stretch=1)

        self._last_generated_key_path: str | None = None
        self._last_generated_alg: str = ""

        return w

    def _browse_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Private Key", "", "PEM Files (*.pem);;All Files (*)")
        if path:
            if not path.endswith(".pem"):
                path += ".pem"
            self._out_edit.setText(path)

    def _do_generate(self):
        alg = self._alg_combo.currentText()
        passphrase = self._pass_edit.text() or None
        confirm = self._pass_confirm.text() or None
        out_path = self._out_edit.text().strip()

        if passphrase and passphrase != confirm:
            self._gen_status.setText("✗  Passphrases do not match")
            self._gen_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return

        if not out_path:
            self._gen_status.setText("✗  Please specify an output path")
            self._gen_status.setStyleSheet("color: #F87171; font-weight: bold;")
            return

        self._btn_generate.setEnabled(False)
        self._gen_status.setText("Generating… (this may take a few seconds for large RSA keys)")
        self._gen_status.setStyleSheet("color: #60A5FA;")

        self.run_in_thread(generate_key, alg, passphrase, out_path, callback=self._on_generate_done)

    def _on_generate_done(self, result: ExecutionResult):
        self._btn_generate.setEnabled(True)
        self.show_result(result, self._gen_output, self._gen_status)

        if result.success:
            priv = result.parsed.get("private_key_path", "")
            pub = result.parsed.get("public_key_path", "")
            alg = result.parsed.get("algorithm", "")
            self._gen_output.setPlainText(
                f"Key pair generated successfully.\n\n"
                f"Algorithm: {alg}\n"
                f"Private key: {priv}\n"
                f"Public key:  {pub}\n\n"
                + result.output
            )
            # Enable "Save to Vault" for the generated key
            self._last_generated_key_path = priv
            self._last_generated_alg = alg
            self._btn_save_vault.setEnabled(bool(priv))
            self._btn_save_vault.setStyleSheet(
                "background:#065F46; color:#34D399; font-weight:bold; padding:8px; border-radius:6px;"
            )
        else:
            self._btn_save_vault.setEnabled(False)

    def _do_save_to_vault(self):
        from modules.vault import controller as vc
        if not vc.is_unlocked():
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.information(
                self, "Vault Locked",
                "The Key Vault is locked.\n\nGo to the Key Vault panel, unlock or create a vault, then come back and click 'Save to Vault' again."
            )
            return
        path = self._last_generated_key_path
        alg = self._last_generated_alg
        if not path:
            return
        # Suggest a name based on algorithm and file
        from pathlib import Path
        suggested_name = f"{alg} — {Path(path).stem}"
        name, ok = _simple_input_dialog(self, "Save to Vault", "Key name in vault:", suggested_name)
        if not ok or not name:
            return
        try:
            eid = vc.import_key_from_file(path, name, alg)
            self._gen_status.setText(f"✓  Key saved to vault (ID: {eid[:8]}…)")
            self._gen_status.setStyleSheet("color:#34D399; font-weight:bold;")
            self._btn_save_vault.setEnabled(False)
            self._btn_save_vault.setStyleSheet("background:#374151; color:#9CA3AF; padding:8px; border-radius:6px;")
        except Exception as e:
            from PyQt6.QtWidgets import QMessageBox
            QMessageBox.critical(self, "Vault Error", f"Failed to save key to vault:\n{e}")

    # ------------------------------------------------------------------
    # Extract Public Key tab
    # ------------------------------------------------------------------

    def _build_extract_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(8)

        info = QLabel(
            "Extract the public key from a private key file.\n"
            "The public key can be shared freely — it contains no secret material."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(info)

        form = QFormLayout()

        priv_row = QHBoxLayout()
        self._ext_priv = QLineEdit()
        self._ext_priv.setPlaceholderText("Private key .pem")
        btn_priv = QPushButton("Browse…")
        btn_priv.setMaximumWidth(80)
        btn_priv.clicked.connect(lambda: self._browse_input(self._ext_priv))
        priv_row.addWidget(self._ext_priv)
        priv_row.addWidget(btn_priv)
        form.addRow("Private key:", priv_row)

        out_row = QHBoxLayout()
        self._ext_out = QLineEdit()
        self._ext_out.setPlaceholderText("public_key.pem")
        btn_out = QPushButton("Browse…")
        btn_out.setMaximumWidth(80)
        btn_out.clicked.connect(self._browse_extract_output)
        out_row.addWidget(self._ext_out)
        out_row.addWidget(btn_out)
        form.addRow("Public key output:", out_row)

        self._ext_pass = QLineEdit()
        self._ext_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._ext_pass.setPlaceholderText("Passphrase if key is encrypted")
        form.addRow("Passphrase:", self._ext_pass)

        layout.addLayout(form)

        btn = QPushButton("Extract Public Key")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_extract)
        layout.addWidget(btn)

        self._ext_status = self.build_status_label()
        layout.addWidget(self._ext_status)

        _, self._ext_output = self.build_output_area("Public Key PEM")
        layout.addWidget(_, stretch=1)

        return w

    def _browse_extract_output(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Public Key", "public_key.pem", "PEM Files (*.pem);;All Files (*)")
        if path:
            if not path.endswith(".pem"):
                path += ".pem"
            self._ext_out.setText(path)

    def _do_extract(self):
        priv = self._ext_priv.text().strip()
        out = self._ext_out.text().strip()
        if not priv or not out:
            self._ext_status.setText("✗  Provide private key path and output path.")
            self._ext_status.setStyleSheet("color:#F87171;")
            return
        passphrase = self._ext_pass.text() or None
        self.run_in_thread(extract_public_key, priv, out, passphrase, callback=self._on_extract_done)

    def _on_extract_done(self, result):
        self.show_result(result, self._ext_output, self._ext_status)
        if result.success:
            path = self._ext_out.text().strip()
            try:
                content = Path(path).read_text()
                self._ext_output.setPlainText(content)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Inspect tab
    # ------------------------------------------------------------------

    def _build_inspect_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(8)

        form = QFormLayout()
        self._insp_path = QLineEdit()
        self._insp_path.setPlaceholderText("Path to private or public key .pem")
        btn_browse_i = QPushButton("Browse…")
        btn_browse_i.setMaximumWidth(80)
        btn_browse_i.clicked.connect(lambda: self._browse_input(self._insp_path))
        row = QHBoxLayout()
        row.addWidget(self._insp_path)
        row.addWidget(btn_browse_i)
        form.addRow("Key file:", row)

        self._insp_pass = QLineEdit()
        self._insp_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._insp_pass.setPlaceholderText("Passphrase (if encrypted)")
        form.addRow("Passphrase:", self._insp_pass)
        layout.addLayout(form)

        btn = QPushButton("Inspect Key")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_inspect)
        layout.addWidget(btn)

        self._insp_status = self.build_status_label()
        layout.addWidget(self._insp_status)

        _, self._insp_output = self.build_output_area("Key Details")
        layout.addWidget(_, stretch=1)

        return w

    def _browse_input(self, line_edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, "Open Key File", "", "PEM Files (*.pem);;All Files (*)")
        if path:
            line_edit.setText(path)

    def _do_inspect(self):
        path = self._insp_path.text().strip()
        if not path:
            return
        passphrase = self._insp_pass.text() or None
        self.run_in_thread(inspect_key, path, passphrase, callback=self._on_inspect_done)

    def _on_inspect_done(self, result: ExecutionResult):
        self.show_result(result, self._insp_output, self._insp_status)
        if result.success and result.parsed:
            details = "\n".join(f"{k}: {v}" for k, v in result.parsed.items() if k != "fingerprint_sha256")
            fp = result.parsed.get("fingerprint_sha256", "")
            extra = f"\n\nFingerprint (SHA-256):\n{fp}" if fp else ""
            self._insp_output.setPlainText(details + extra + "\n\n" + result.stdout)

    # ------------------------------------------------------------------
    # Convert tab
    # ------------------------------------------------------------------

    def _build_convert_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setSpacing(8)

        form = QFormLayout()
        self._conv_in = QLineEdit()
        self._conv_in.setPlaceholderText("Input key file")
        btn_ci = QPushButton("Browse…")
        btn_ci.setMaximumWidth(80)
        btn_ci.clicked.connect(lambda: self._browse_input(self._conv_in))
        row_in = QHBoxLayout()
        row_in.addWidget(self._conv_in)
        row_in.addWidget(btn_ci)
        form.addRow("Input file:", row_in)

        self._conv_infmt = QComboBox()
        self._conv_infmt.addItems(["PEM", "DER"])
        form.addRow("Input format:", self._conv_infmt)

        self._conv_outfmt = QComboBox()
        self._conv_outfmt.addItems(["PEM", "DER", "PKCS8", "PKCS1"])
        form.addRow("Output format:", self._conv_outfmt)

        self._conv_out = QLineEdit()
        self._conv_out.setPlaceholderText("Output file path")
        btn_co = QPushButton("Browse…")
        btn_co.setMaximumWidth(80)
        btn_co.clicked.connect(lambda: self._browse_input(self._conv_out))
        row_out = QHBoxLayout()
        row_out.addWidget(self._conv_out)
        row_out.addWidget(btn_co)
        form.addRow("Output file:", row_out)

        self._conv_pass = QLineEdit()
        self._conv_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._conv_pass.setPlaceholderText("Passphrase (if key is encrypted)")
        form.addRow("Passphrase:", self._conv_pass)

        layout.addLayout(form)

        btn = QPushButton("Convert Key")
        btn.setStyleSheet("background:#1D4ED8; color:white; padding:8px; border-radius:6px;")
        btn.clicked.connect(self._do_convert)
        layout.addWidget(btn)

        self._conv_status = self.build_status_label()
        layout.addWidget(self._conv_status)

        _, self._conv_output = self.build_output_area("Result")
        layout.addWidget(_, stretch=1)

        return w

    def _do_convert(self):
        inp = self._conv_in.text().strip()
        out = self._conv_out.text().strip()
        if not inp or not out:
            return
        infmt = self._conv_infmt.currentText()
        outfmt = self._conv_outfmt.currentText()
        passphrase = self._conv_pass.text() or None
        self.run_in_thread(convert_key, inp, out, infmt, outfmt, passphrase, callback=self._on_convert_done)

    def _on_convert_done(self, result: ExecutionResult):
        self.show_result(result, self._conv_output, self._conv_status)

    # ------------------------------------------------------------------
    # Mode switch
    # ------------------------------------------------------------------

    def set_expert_mode(self, expert: bool):
        self._expert = expert
        self._alg_combo.clear()
        if expert:
            from modules.keymgmt.controller import ALL_ALGORITHMS
            self._alg_combo.addItems(ALL_ALGORITHMS)
        else:
            self._alg_combo.addItems(BEGINNER_ALGORITHMS)
