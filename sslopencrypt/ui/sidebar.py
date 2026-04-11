"""
ui/sidebar.py — Left sidebar Module Navigator.

Shows module icons and names. Clicking switches the central workspace.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

MODULE_LIST = [
    ("keymgmt",   "🔑", "Key Management"),
    ("symmetric",  "🔒", "Symmetric Encryption"),
    ("hashing",    "🔢", "Hashing & Digests"),
    ("pki",        "📜", "PKI & Certificates"),
    ("signing",    "✍️",  "Document Signing"),
    ("smime",      "📧", "S/MIME & Email"),
    ("random",     "🎲", "Secure Random"),
    ("tls",        "🌐", "TLS Advisor"),
    ("edu",        "🎓", "Educational Hub"),
    ("gpg",        "🔐", "GnuPG / OpenPGP"),
    ("vault",      "🔒", "Key Vault"),
    ("india_dsc",  "🇮🇳", "India DSC & eSign"),
]


class SidebarButton(QPushButton):
    def __init__(self, module_id: str, icon: str, label: str, parent=None):
        super().__init__(parent)
        self.module_id = module_id
        self.setText(f"{icon}  {label}")
        self.setCheckable(True)
        self.setFlat(True)
        self.setFont(QFont("Segoe UI", 10))
        self.setMinimumHeight(44)
        self.setStyleSheet(self._style_normal())
        self.setToolTip(label)

    def _style_normal(self):
        return """
QPushButton {
    text-align: left;
    padding: 8px 12px;
    border: none;
    border-radius: 6px;
    color: #D1D5DB;
    background: transparent;
}
QPushButton:hover {
    background: #374151;
    color: #F9FAFB;
}
QPushButton:checked {
    background: #1D4ED8;
    color: white;
    font-weight: bold;
}
"""


class Sidebar(QWidget):
    """Left sidebar that emits module_selected(module_id) when a button is clicked."""

    module_selected = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(200)
        self.setStyleSheet("background-color: #1F2937;")

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 8)
        outer.setSpacing(2)

        # App title
        title = QLabel("ssl\nOpenCrypt")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #60A5FA; font-size: 16px; font-weight: bold; padding: 8px 0;")
        outer.addWidget(title)

        sep = QLabel()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background: #374151; margin: 4px 0;")
        outer.addWidget(sep)

        # Scroll area for buttons
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("border: none; background: transparent;")

        btn_container = QWidget()
        btn_container.setStyleSheet("background: transparent;")
        btn_layout = QVBoxLayout(btn_container)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(2)

        self._buttons: dict[str, SidebarButton] = {}
        for mod_id, icon, label in MODULE_LIST:
            btn = SidebarButton(mod_id, icon, label)
            btn.clicked.connect(lambda checked, mid=mod_id: self._on_clicked(mid))
            btn_layout.addWidget(btn)
            self._buttons[mod_id] = btn

        btn_layout.addStretch()
        scroll.setWidget(btn_container)
        outer.addWidget(scroll, stretch=1)

        # Select first module by default
        self.select_module("keymgmt")

    def _on_clicked(self, module_id: str):
        self.select_module(module_id)
        self.module_selected.emit(module_id)

    def select_module(self, module_id: str):
        for mid, btn in self._buttons.items():
            btn.setChecked(mid == module_id)
