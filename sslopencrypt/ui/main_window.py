"""
ui/main_window.py — sslOpenCrypt main application window.

Layout (spec §4.2):
  Left sidebar   — Module Navigator
  Central workspace — active module panel
  Right panel    — (collapsible, future: property inspector)
  Bottom panel   — Command Console (hidden in Beginner Mode)
"""

import sys
from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QAction, QFont, QIcon, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFormLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenuBar,
    QPushButton, QScrollArea, QSplitter, QStatusBar,
    QToolBar, QVBoxLayout, QWidget, QStackedWidget,
    QMessageBox, QFileDialog,
)

from .app_state import AppMode, app_state
from .sidebar import Sidebar
from .command_console import CommandConsole

from .panels.keymgmt_panel import KeyMgmtPanel
from .panels.symmetric_panel import SymmetricPanel
from .panels.hashing_panel import HashingPanel
from .panels.pki_panel import PKIPanel
from .panels.signing_panel import SigningPanel
from .panels.smime_panel import SMIMEPanel
from .panels.random_panel import RandomPanel
from .panels.tls_panel import TLSPanel
from .panels.edu_panel import EduPanel
from .panels.gpg_panel import GPGPanel
from .panels.vault_panel import VaultPanel
from .panels.india_dsc_panel import IndiaDSCPanel

from core.executor import get_openssl_path, openssl_version
from core.audit_log import export_log


class _VersionWorker(QObject):
    done = pyqtSignal(str)

    def run(self):
        try:
            ver = openssl_version()
        except Exception as e:
            ver = str(e)
        self.done.emit(ver)


APP_STYLESHEET = """
QMainWindow {
    background-color: #111827;
}
QWidget {
    color: #E5E7EB;
    font-family: "Segoe UI", "Noto Sans", Arial, sans-serif;
    font-size: 10pt;
}
QTabWidget::pane {
    border: 1px solid #374151;
    background: #1F2937;
    border-radius: 4px;
}
QTabBar::tab {
    background: #374151;
    color: #9CA3AF;
    padding: 6px 14px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #1D4ED8;
    color: white;
    font-weight: bold;
}
QTabBar::tab:hover {
    background: #4B5563;
    color: white;
}
QLineEdit, QTextEdit, QComboBox, QSpinBox {
    background: #374151;
    border: 1px solid #4B5563;
    border-radius: 4px;
    padding: 4px 8px;
    color: #E5E7EB;
}
QLineEdit:focus, QTextEdit:focus {
    border: 1px solid #3B82F6;
}
QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}
QPushButton {
    background: #374151;
    color: #E5E7EB;
    border: none;
    border-radius: 4px;
    padding: 6px 12px;
}
QPushButton:hover {
    background: #4B5563;
}
QPushButton:pressed {
    background: #1D4ED8;
}
QPushButton:disabled {
    background: #1F2937;
    color: #4B5563;
}
QCheckBox {
    spacing: 6px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border-radius: 3px;
    border: 2px solid #4B5563;
    background: #374151;
}
QCheckBox::indicator:checked {
    background: #1D4ED8;
    border: 2px solid #1D4ED8;
}
QScrollBar:vertical {
    background: #1F2937;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #4B5563;
    border-radius: 4px;
}
QFormLayout QLabel {
    color: #9CA3AF;
    font-size: 9pt;
}
QStatusBar {
    background: #1F2937;
    color: #6B7280;
    font-size: 9pt;
}
QMenuBar {
    background: #1F2937;
    color: #D1D5DB;
}
QMenuBar::item:selected {
    background: #374151;
}
QMenu {
    background: #1F2937;
    border: 1px solid #374151;
}
QMenu::item:selected {
    background: #1D4ED8;
}
QSplitter::handle {
    background: #374151;
}
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("sslOpenCrypt — Open-Source GUI for OpenSSL, PKI & Encryption")
        self.resize(1300, 820)
        self.setMinimumSize(900, 600)
        self.setStyleSheet(APP_STYLESHEET)

        self._panels: dict[str, QWidget] = {}
        self._setup_statusbar()   # must come before _setup_ui (which calls showMessage)
        self._setup_ui()
        self._setup_menu()
        self._fetch_openssl_version()

        # Connect app_state
        app_state.mode_changed.connect(self._on_mode_changed)
        app_state.openssl_version_ready.connect(self._on_version_ready)

        # Default: Beginner Mode
        self._apply_mode(AppMode.BEGINNER)

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Mode toggle toolbar
        root_layout.addWidget(self._build_mode_bar())

        # Main horizontal splitter: sidebar | workspace
        main_splitter = QSplitter(Qt.Orientation.Horizontal)
        main_splitter.setHandleWidth(2)

        # Sidebar
        self._sidebar = Sidebar()
        self._sidebar.module_selected.connect(self._show_module)
        main_splitter.addWidget(self._sidebar)

        # Vertical splitter: panel | console
        self._v_splitter = QSplitter(Qt.Orientation.Vertical)
        self._v_splitter.setHandleWidth(3)

        # Stacked workspace
        self._stack = QStackedWidget()
        self._stack.setStyleSheet("background: #111827;")
        self._v_splitter.addWidget(self._stack)

        # Command console (bottom)
        self._console = CommandConsole()
        self._console.setVisible(False)
        self._v_splitter.addWidget(self._console)
        self._v_splitter.setStretchFactor(0, 3)
        self._v_splitter.setStretchFactor(1, 1)

        main_splitter.addWidget(self._v_splitter)
        main_splitter.setStretchFactor(0, 0)
        main_splitter.setStretchFactor(1, 1)

        root_layout.addWidget(main_splitter, stretch=1)

        # Build module panels
        self._build_panels()

        # Default panel
        self._show_module("keymgmt")

    def _build_mode_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(40)
        bar.setStyleSheet("background: #1F2937; border-bottom: 1px solid #374151;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 4, 12, 4)

        logo = QLabel("sslOpenCrypt")
        logo.setStyleSheet("font-weight: bold; font-size: 13px; color: #60A5FA;")
        layout.addWidget(logo)

        layout.addStretch()

        # Mode toggle buttons
        self._btn_beginner = QPushButton("🌱  Beginner")
        self._btn_beginner.setCheckable(True)
        self._btn_beginner.setChecked(True)
        self._btn_beginner.setToolTip("Beginner Mode: simplified interface, Command Console hidden")

        self._btn_expert = QPushButton("⚙️  Expert")
        self._btn_expert.setCheckable(True)
        self._btn_expert.setToolTip("Expert Mode: Command Console visible, all algorithms exposed")

        self._btn_classroom = QPushButton("🎓  Classroom")
        self._btn_classroom.setCheckable(True)
        self._btn_classroom.setToolTip("Classroom Mode: session logging, lab report export")

        for btn in [self._btn_beginner, self._btn_expert, self._btn_classroom]:
            btn.setStyleSheet("""
QPushButton { background: #374151; color: #9CA3AF; padding: 4px 12px; border-radius: 14px; font-size: 9pt; }
QPushButton:checked { background: #1D4ED8; color: white; font-weight: bold; }
QPushButton:hover { background: #4B5563; }
""")
            layout.addWidget(btn)

        self._btn_beginner.clicked.connect(lambda: self._set_mode(AppMode.BEGINNER))
        self._btn_expert.clicked.connect(lambda: self._set_mode(AppMode.EXPERT))
        self._btn_classroom.clicked.connect(lambda: self._set_mode(AppMode.CLASSROOM))

        return bar

    def _build_panels(self):
        """Instantiate all module panels and add them to the stack."""
        panel_classes = [
            ("keymgmt",  KeyMgmtPanel),
            ("symmetric", SymmetricPanel),
            ("hashing",  HashingPanel),
            ("pki",      PKIPanel),
            ("signing",  SigningPanel),
            ("smime",    SMIMEPanel),
            ("random",   RandomPanel),
            ("tls",      TLSPanel),
            ("edu",      EduPanel),
            ("gpg",      GPGPanel),
            ("vault",    VaultPanel),
            ("india_dsc", IndiaDSCPanel),
        ]
        for module_id, PanelClass in panel_classes:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet("border: none; background: #111827;")
            panel = PanelClass()
            panel.result_ready.connect(self._on_result)
            scroll.setWidget(panel)
            self._stack.addWidget(scroll)
            self._panels[module_id] = panel

    def _setup_menu(self):
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)

        # File menu
        file_menu = menubar.addMenu("File")
        action_export_log = QAction("Export Audit Log…", self)
        action_export_log.triggered.connect(self._export_audit_log)
        file_menu.addAction(action_export_log)

        self._action_export_report = QAction("Export Lab Report…", self)
        self._action_export_report.triggered.connect(self._export_lab_report)
        self._action_export_report.setEnabled(False)  # enabled only in Classroom mode
        file_menu.addAction(self._action_export_report)

        file_menu.addSeparator()
        action_quit = QAction("Quit", self)
        action_quit.setShortcut(QKeySequence("Ctrl+Q"))
        action_quit.triggered.connect(self.close)
        file_menu.addAction(action_quit)

        # Mode menu
        mode_menu = menubar.addMenu("Mode")
        for mode, label in [(AppMode.BEGINNER, "Beginner"), (AppMode.EXPERT, "Expert"), (AppMode.CLASSROOM, "Classroom")]:
            action = QAction(label, self)
            action.triggered.connect(lambda checked, m=mode: self._set_mode(m))
            mode_menu.addAction(action)

        # Help menu
        help_menu = menubar.addMenu("Help")
        about_action = QAction("About sslOpenCrypt", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_statusbar(self):
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)
        self._statusbar.showMessage("Ready")

        self._openssl_label = QLabel("OpenSSL: detecting…")
        self._openssl_label.setStyleSheet("color: #6B7280; font-size: 9pt; padding-right: 8px;")
        self._statusbar.addPermanentWidget(self._openssl_label)

        self._mode_label = QLabel("Mode: Beginner")
        self._mode_label.setStyleSheet("color: #6B7280; font-size: 9pt; padding-right: 8px;")
        self._statusbar.addPermanentWidget(self._mode_label)

    # ------------------------------------------------------------------
    # Async OpenSSL version detection
    # ------------------------------------------------------------------

    def _fetch_openssl_version(self):
        worker_obj = _VersionWorker()
        thread = QThread()
        worker_obj.moveToThread(thread)
        thread.started.connect(worker_obj.run)
        worker_obj.done.connect(self._on_version_ready)
        worker_obj.done.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        self._version_thread = thread
        thread.start()

    def _on_version_ready(self, version: str):
        app_state.openssl_version = version
        self._openssl_label.setText(f"OpenSSL: {version}")

    # ------------------------------------------------------------------
    # Module navigation
    # ------------------------------------------------------------------

    def _show_module(self, module_id: str):
        keys = list(self._panels.keys())
        if module_id in keys:
            idx = keys.index(module_id)
            self._stack.setCurrentIndex(idx)
        self._sidebar.select_module(module_id)
        self._statusbar.showMessage(f"Module: {module_id}")

    # ------------------------------------------------------------------
    # Result handling — forward to Command Console
    # ------------------------------------------------------------------

    def _on_result(self, result):
        if result and result.command_str:
            self._console.append_result(result)

    # ------------------------------------------------------------------
    # Mode switching
    # ------------------------------------------------------------------

    def _set_mode(self, mode: AppMode):
        for btn, m in [
            (self._btn_beginner, AppMode.BEGINNER),
            (self._btn_expert, AppMode.EXPERT),
            (self._btn_classroom, AppMode.CLASSROOM),
        ]:
            btn.setChecked(m == mode)
        app_state.mode = mode

    def _on_mode_changed(self, mode: AppMode):
        self._apply_mode(mode)

    def _apply_mode(self, mode: AppMode):
        is_expert = mode in (AppMode.EXPERT, AppMode.CLASSROOM)
        self._console.setVisible(is_expert)
        self._console.set_expert_mode(is_expert)

        mode_names = {AppMode.BEGINNER: "Beginner", AppMode.EXPERT: "Expert", AppMode.CLASSROOM: "Classroom"}
        self._mode_label.setText(f"Mode: {mode_names.get(mode, mode.value)}")

        # Classroom Mode: start/stop session log
        try:
            from core import session_log
            if mode == AppMode.CLASSROOM:
                if not session_log.is_active():
                    self._start_classroom_session()
            else:
                if session_log.is_active():
                    session_log.stop_session()
        except Exception:
            pass

        # Enable/disable lab report export menu item
        if hasattr(self, "_action_export_report"):
            self._action_export_report.setEnabled(mode == AppMode.CLASSROOM)

        # Propagate to panels that support it
        for panel in self._panels.values():
            if hasattr(panel, "set_expert_mode"):
                panel.set_expert_mode(is_expert)

    # ------------------------------------------------------------------
    # Menu actions
    # ------------------------------------------------------------------

    def _start_classroom_session(self):
        """Show a dialog to collect student name and session title, then start session."""
        from core import session_log

        dlg = QDialog(self)
        dlg.setWindowTitle("Start Classroom Session")
        dlg.setModal(True)
        dlg.setMinimumWidth(380)
        dlg.setStyleSheet(self.styleSheet())
        layout = QVBoxLayout(dlg)
        layout.setSpacing(12)

        info = QLabel(
            "Classroom Mode records all cryptographic operations to a session log "
            "which can be exported as an HTML lab report."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(info)

        form = QFormLayout()
        form.setSpacing(8)
        name_edit = QLineEdit()
        name_edit.setPlaceholderText("e.g. Alice Smith")
        form.addRow("Student name:", name_edit)

        title_edit = QLineEdit()
        title_edit.setPlaceholderText("e.g. Lab 3 – PKI & Certificates")
        title_edit.setText("Cryptography Lab Session")
        form.addRow("Session title:", title_edit)
        layout.addLayout(form)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(dlg.accept)
        btn_box.rejected.connect(dlg.reject)
        layout.addWidget(btn_box)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            session_log.start_session(
                student_name=name_edit.text().strip(),
                session_title=title_edit.text().strip() or "Cryptography Lab Session",
            )
            self._statusbar.showMessage(
                f"Classroom session started — {session_log.get_session_info()['session_title']}"
            )
        else:
            # User cancelled — revert to Expert mode
            self._set_mode(AppMode.EXPERT)

    def _export_audit_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Audit Log", "audit_log.json", "JSON (*.json);;All Files (*)")
        if path:
            export_log(path)
            self._statusbar.showMessage(f"Audit log exported to {path}")

    def _export_lab_report(self):
        from core import session_log
        from core.lab_report import generate_html_report_file
        if not session_log.is_active():
            QMessageBox.warning(self, "No Session", "No active Classroom session. Switch to Classroom Mode first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Lab Report", "lab_report.html", "HTML Files (*.html);;All Files (*)"
        )
        if path:
            try:
                generate_html_report_file(path, session_log.get_session_info(), session_log.get_entries())
                self._statusbar.showMessage(f"Lab report exported to {path}")
                QMessageBox.information(self, "Lab Report", f"Report saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export report: {e}")

    def _show_about(self):
        QMessageBox.about(
            self,
            "About sslOpenCrypt",
            "<h2>sslOpenCrypt</h2>"
            "<p>Version 1.0 Stable — Open-Source GUI for OpenSSL, PKI &amp; Encryption</p>"
            "<p>Built on PyQt6 + OpenSSL CLI. Licensed under <b>GPL v3</b>.</p>"
            "<p>Philosophy: every operation shows the real <code>openssl</code> command.<br>"
            "Using sslOpenCrypt is simultaneously using OpenSSL — and learning it.</p>"
            "<p><a href='https://tctech.co.in'>tctech.co.in</a></p>"
        )


def run_app():
    """Entry point — create and run the Qt application."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("sslOpenCrypt")
    app.setOrganizationName("tctech.co.in")
    app.setApplicationVersion("1.0.0")

    window = MainWindow()
    window.show()
    return app.exec()
