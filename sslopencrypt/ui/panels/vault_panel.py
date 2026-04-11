"""
ui/panels/vault_panel.py — Module 11: Key Vault panel.

Provides a GUI for the encrypted key vault:
  - Create / unlock vault
  - List stored keys
  - Add key from file or from keymgmt session
  - Export key to temp file for use in operations
  - Delete key
  - Change master passphrase
  - Vault statistics
"""

import os
import tempfile

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog,
    QFormLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMessageBox, QPushButton, QSizePolicy, QStackedWidget,
    QTabWidget, QTableWidget, QTableWidgetItem, QTextEdit,
    QVBoxLayout, QWidget,
)

from .base_panel import BasePanel


# ---------------------------------------------------------------------------
# Helper dialogs
# ---------------------------------------------------------------------------

class _PassphraseDialog(QDialog):
    """Single-passphrase entry dialog."""
    def __init__(self, title: str, label: str, confirm: bool = False, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(360)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(QLabel(label))

        self._edit = QLineEdit()
        self._edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._edit.setPlaceholderText("Enter passphrase…")
        layout.addWidget(self._edit)

        self._confirm_edit: QLineEdit | None = None
        if confirm:
            lbl2 = QLabel("Confirm passphrase:")
            layout.addWidget(lbl2)
            self._confirm_edit = QLineEdit()
            self._confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self._confirm_edit.setPlaceholderText("Re-enter passphrase…")
            layout.addWidget(self._confirm_edit)

        show_cb = QCheckBox("Show passphrase")
        show_cb.toggled.connect(lambda on: self._edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
        ))
        if self._confirm_edit:
            show_cb.toggled.connect(lambda on: self._confirm_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
            ))
        layout.addWidget(show_cb)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(self._on_accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

        self._result: str | None = None

    def _on_accept(self):
        passphrase = self._edit.text()
        if not passphrase:
            QMessageBox.warning(self, "Error", "Passphrase cannot be empty.")
            return
        if self._confirm_edit is not None:
            if passphrase != self._confirm_edit.text():
                QMessageBox.warning(self, "Error", "Passphrases do not match.")
                return
        self._result = passphrase
        self.accept()

    def passphrase(self) -> str | None:
        return self._result


class _AddKeyDialog(QDialog):
    """Dialog to add a key to the vault."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Key to Vault")
        self.setModal(True)
        self.setMinimumWidth(440)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        form = QFormLayout()

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText("e.g. Production ECDSA Key")
        form.addRow("Key name:", self._name_edit)

        self._alg_edit = QLineEdit()
        self._alg_edit.setPlaceholderText("e.g. ECDSA-P256, RSA-2048, Ed25519")
        form.addRow("Algorithm:", self._alg_edit)

        self._tags_edit = QLineEdit()
        self._tags_edit.setPlaceholderText("comma-separated: firmware, production")
        form.addRow("Tags:", self._tags_edit)

        self._comment_edit = QLineEdit()
        self._comment_edit.setPlaceholderText("Optional description")
        form.addRow("Comment:", self._comment_edit)

        layout.addLayout(form)

        # File picker
        file_row = QHBoxLayout()
        self._file_edit = QLineEdit()
        self._file_edit.setPlaceholderText("Private key PEM file…")
        self._file_edit.setReadOnly(True)
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse_file)
        file_row.addWidget(self._file_edit, stretch=1)
        file_row.addWidget(browse_btn)
        layout.addWidget(QLabel("Private key file (.pem):"))
        layout.addLayout(file_row)

        # Or paste PEM
        layout.addWidget(QLabel("— or paste PEM content directly —"))
        self._pem_edit = QTextEdit()
        self._pem_edit.setPlaceholderText("-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----")
        self._pem_edit.setFont(QFont("Monospace", 8))
        self._pem_edit.setMaximumHeight(120)
        layout.addWidget(self._pem_edit)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(self._on_accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

        self._result: dict | None = None

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Private Key", "", "PEM Files (*.pem);;All Files (*)"
        )
        if path:
            self._file_edit.setText(path)
            try:
                with open(path, "r") as f:
                    self._pem_edit.setPlainText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not read file: {e}")

    def _on_accept(self):
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Error", "Key name is required.")
            return
        pem = self._pem_edit.toPlainText().strip()
        if not pem:
            QMessageBox.warning(self, "Error", "No key content provided.")
            return
        if "PRIVATE KEY" not in pem:
            QMessageBox.warning(self, "Warning",
                "Content does not look like a private key PEM. Proceed anyway?")
        tags = [t.strip() for t in self._tags_edit.text().split(",") if t.strip()]
        self._result = {
            "name":     name,
            "algorithm": self._alg_edit.text().strip() or "Unknown",
            "pem":      pem,
            "tags":     tags,
            "comment":  self._comment_edit.text().strip(),
        }
        self.accept()

    def result_data(self) -> dict | None:
        return self._result


# ---------------------------------------------------------------------------
# Locked state widget
# ---------------------------------------------------------------------------

class _LockedWidget(QWidget):
    unlock_requested  = pyqtSignal(str)   # passphrase
    create_requested  = pyqtSignal(str)   # passphrase

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        icon = QLabel("🔒")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size: 48px;")
        layout.addWidget(icon)

        title = QLabel("Key Vault")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        desc = QLabel(
            "Store private keys in an Argon2id-hardened AES-256-GCM encrypted container.\n"
            "Keys never leave the vault in plaintext."
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9CA3AF; font-size: 11px; max-width: 400px;")
        layout.addWidget(desc)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Master passphrase…")
        self._pass_edit.setMaximumWidth(320)
        self._pass_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pass_edit.returnPressed.connect(self._on_unlock)
        layout.addWidget(self._pass_edit, alignment=Qt.AlignmentFlag.AlignCenter)

        show_cb = QCheckBox("Show passphrase")
        show_cb.toggled.connect(lambda on: self._pass_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password
        ))
        layout.addWidget(show_cb, alignment=Qt.AlignmentFlag.AlignCenter)

        btn_row = QHBoxLayout()
        unlock_btn = QPushButton("🔓  Unlock Vault")
        unlock_btn.setStyleSheet("background:#1D4ED8;color:white;font-weight:bold;padding:8px 20px;")
        unlock_btn.clicked.connect(self._on_unlock)

        create_btn = QPushButton("✨  Create New Vault")
        create_btn.setStyleSheet("background:#374151;color:#D1D5DB;padding:8px 20px;")
        create_btn.clicked.connect(self._on_create)

        btn_row.addWidget(unlock_btn)
        btn_row.addWidget(create_btn)
        layout.addLayout(btn_row)

        self._status = QLabel()
        self._status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._status.setStyleSheet("font-size: 11px; color: #F87171;")
        layout.addWidget(self._status)

    def _on_unlock(self):
        pw = self._pass_edit.text()
        if not pw:
            self._status.setText("Passphrase required.")
            return
        self.unlock_requested.emit(pw)

    def _on_create(self):
        pw = self._pass_edit.text()
        if not pw:
            self._status.setText("Choose a master passphrase first.")
            return
        self.create_requested.emit(pw)

    def set_error(self, msg: str):
        self._status.setText(msg)
        self._status.setStyleSheet("font-size:11px;color:#F87171;")

    def set_success(self, msg: str):
        self._status.setText(msg)
        self._status.setStyleSheet("font-size:11px;color:#34D399;")


# ---------------------------------------------------------------------------
# Unlocked state widget
# ---------------------------------------------------------------------------

class _UnlockedWidget(QWidget):
    lock_requested = pyqtSignal()
    refresh_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Toolbar
        toolbar = QHBoxLayout()
        self._stats_label = QLabel("Vault unlocked")
        self._stats_label.setStyleSheet("color:#34D399;font-size:11px;font-weight:bold;")
        toolbar.addWidget(self._stats_label)
        toolbar.addStretch()

        add_btn = QPushButton("➕  Add Key")
        add_btn.clicked.connect(self._on_add_key)
        toolbar.addWidget(add_btn)

        export_btn = QPushButton("📤  Export Selected")
        export_btn.clicked.connect(self._on_export_key)
        toolbar.addWidget(export_btn)

        del_btn = QPushButton("🗑  Delete Selected")
        del_btn.setStyleSheet("background:#7F1D1D;color:#FCA5A5;")
        del_btn.clicked.connect(self._on_delete_key)
        toolbar.addWidget(del_btn)

        change_pass_btn = QPushButton("🔑  Change Passphrase")
        change_pass_btn.clicked.connect(self._on_change_passphrase)
        toolbar.addWidget(change_pass_btn)

        lock_btn = QPushButton("🔒  Lock")
        lock_btn.setStyleSheet("background:#374151;color:#9CA3AF;")
        lock_btn.clicked.connect(self.lock_requested.emit)
        toolbar.addWidget(lock_btn)

        layout.addLayout(toolbar)

        # Key table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Name", "Algorithm", "Tags", "Comment", "Created"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setStyleSheet(
            "QTableWidget { background:#1F2937; gridline-color:#374151; }"
            "QTableWidget::item:selected { background:#1D4ED8; }"
            "QHeaderView::section { background:#374151; color:#9CA3AF; padding:6px; "
            "border:none; font-size:10px; }"
        )
        layout.addWidget(self._table)

        # Status
        self._status = QLabel()
        self._status.setStyleSheet("font-size:11px;color:#9CA3AF;")
        layout.addWidget(self._status)

        self._entries: list[dict] = []

    def refresh(self, entries: list[dict], stats: dict):
        self._entries = entries
        count = stats.get("total_keys", len(entries))
        self._stats_label.setText(
            f"🔓 Vault unlocked  ·  {count} key{'s' if count != 1 else ''}"
        )
        self._table.setRowCount(0)
        for e in entries:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table.setItem(row, 0, QTableWidgetItem(e.get("name", "")))
            self._table.setItem(row, 1, QTableWidgetItem(e.get("algorithm", "")))
            self._table.setItem(row, 2, QTableWidgetItem(", ".join(e.get("tags", []))))
            self._table.setItem(row, 3, QTableWidgetItem(e.get("comment", "")))
            created = e.get("created_at", "")[:10]
            self._table.setItem(row, 4, QTableWidgetItem(created))
            # Store entry id in UserRole of first cell
            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, e["id"])

    def _selected_entry_id(self) -> str | None:
        rows = self._table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self._table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _on_add_key(self):
        dlg = _AddKeyDialog(self)
        dlg.setStyleSheet(self.window().styleSheet() if self.window() else "")
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        data = dlg.result_data()
        if not data:
            return
        try:
            from modules.vault.controller import add_key
            add_key(
                name=data["name"],
                algorithm=data["algorithm"],
                pem=data["pem"],
                tags=data["tags"],
                comment=data["comment"],
            )
            self._status.setText(f"✓  Key '{data['name']}' added to vault.")
            self._status.setStyleSheet("font-size:11px;color:#34D399;")
            self.refresh_requested.emit()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add key: {e}")

    def _on_export_key(self):
        entry_id = self._selected_entry_id()
        if not entry_id:
            QMessageBox.information(self, "Select a key", "Please select a key to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Private Key", "private_key.pem",
            "PEM Files (*.pem);;All Files (*)"
        )
        if not path:
            return
        try:
            from modules.vault.controller import export_key_to_file
            export_key_to_file(entry_id, path)
            self._status.setText(f"✓  Key exported to {path}  (delete after use!)")
            self._status.setStyleSheet("font-size:11px;color:#FCD34D;")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Export failed: {e}")

    def _on_delete_key(self):
        entry_id = self._selected_entry_id()
        if not entry_id:
            QMessageBox.information(self, "Select a key", "Please select a key to delete.")
            return
        rows = self._table.selectionModel().selectedRows()
        name = self._table.item(rows[0].row(), 0).text() if rows else "this key"
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Permanently delete '{name}' from the vault? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            from modules.vault.controller import remove_key
            remove_key(entry_id)
            self._status.setText(f"✓  '{name}' removed from vault.")
            self._status.setStyleSheet("font-size:11px;color:#34D399;")
            self.refresh_requested.emit()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Delete failed: {e}")

    def _on_change_passphrase(self):
        old_dlg = _PassphraseDialog("Change Passphrase", "Current passphrase:", parent=self)
        old_dlg.setStyleSheet(self.window().styleSheet() if self.window() else "")
        if old_dlg.exec() != QDialog.DialogCode.Accepted or not old_dlg.passphrase():
            return
        new_dlg = _PassphraseDialog(
            "Change Passphrase", "New passphrase:", confirm=True, parent=self
        )
        new_dlg.setStyleSheet(self.window().styleSheet() if self.window() else "")
        if new_dlg.exec() != QDialog.DialogCode.Accepted or not new_dlg.passphrase():
            return
        try:
            from modules.vault.controller import change_passphrase
            change_passphrase(old_dlg.passphrase(), new_dlg.passphrase())
            self._status.setText("✓  Master passphrase changed successfully.")
            self._status.setStyleSheet("font-size:11px;color:#34D399;")
        except ValueError as e:
            QMessageBox.critical(self, "Error", str(e))


# ---------------------------------------------------------------------------
# VaultPanel (BasePanel subclass)
# ---------------------------------------------------------------------------

class VaultPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
        self._check_vault_state()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(8)

        # Title row
        title_row = QHBoxLayout()
        title = QLabel("🔒  Key Vault")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        title_row.addWidget(title)
        title_row.addStretch()
        info_lbl = QLabel(
            "Argon2id · AES-256-GCM · ~/.sslopencrypt/vault.enc"
        )
        info_lbl.setStyleSheet("color: #4B5563; font-size: 10px;")
        title_row.addWidget(info_lbl)
        layout.addLayout(title_row)

        # Stacked: locked / unlocked
        self._stack = QStackedWidget()

        self._locked_widget = _LockedWidget()
        self._locked_widget.unlock_requested.connect(self._on_unlock)
        self._locked_widget.create_requested.connect(self._on_create)
        self._stack.addWidget(self._locked_widget)

        self._unlocked_widget = _UnlockedWidget()
        self._unlocked_widget.lock_requested.connect(self._on_lock)
        self._unlocked_widget.refresh_requested.connect(self._refresh_table)
        self._stack.addWidget(self._unlocked_widget)

        layout.addWidget(self._stack, stretch=1)

    def _check_vault_state(self):
        from modules.vault.controller import is_unlocked, is_vault_exists
        if is_unlocked():
            self._stack.setCurrentIndex(1)
            self._refresh_table()
        else:
            self._stack.setCurrentIndex(0)

    def _on_unlock(self, passphrase: str):
        try:
            from modules.vault.controller import unlock_vault
            unlock_vault(passphrase)
            self._locked_widget.set_success("Vault unlocked.")
            self._stack.setCurrentIndex(1)
            self._refresh_table()
        except FileNotFoundError:
            self._locked_widget.set_error("No vault found. Use 'Create New Vault'.")
        except ValueError as e:
            self._locked_widget.set_error(str(e))
        except Exception as e:
            self._locked_widget.set_error(f"Error: {e}")

    def _on_create(self, passphrase: str):
        from modules.vault.controller import is_vault_exists
        if is_vault_exists():
            reply = QMessageBox.question(
                self, "Vault Already Exists",
                "A vault file already exists. Overwrite it? All existing keys will be lost.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        try:
            from modules.vault.controller import create_vault
            create_vault(passphrase)
            self._locked_widget.set_success("New vault created and unlocked.")
            self._stack.setCurrentIndex(1)
            self._refresh_table()
        except Exception as e:
            self._locked_widget.set_error(f"Error: {e}")

    def _on_lock(self):
        from modules.vault.controller import lock_vault
        lock_vault()
        self._stack.setCurrentIndex(0)

    def _refresh_table(self):
        try:
            from modules.vault.controller import list_keys, vault_stats
            entries = list_keys()
            stats = vault_stats()
            self._unlocked_widget.refresh(entries, stats)
        except RuntimeError:
            self._stack.setCurrentIndex(0)

    def set_expert_mode(self, expert: bool):
        pass  # vault panel is always fully shown
