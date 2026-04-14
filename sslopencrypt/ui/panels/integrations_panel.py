"""
ui/panels/integrations_panel.py — Desktop Integrations panel.

Provides one-click install/uninstall for:
  - LibreOffice integration (macro library + Ctrl+Alt+S/E/H/V shortcuts + toolbar)
  - Dolphin (KDE) service menu
  - Nautilus (GNOME) extension

Also controls the LibreOffice IPC server (localhost:47251) that the
macro shortcuts call at runtime.
"""

import socket
import subprocess
import sys
from pathlib import Path

from PyQt6.QtCore import Qt, QObject, QProcess, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QPushButton,
    QTabWidget, QTextEdit, QVBoxLayout, QWidget,
)

from .base_panel import BasePanel

# Sentinel used when a command path does not exist on disk
_CMD_NOT_FOUND = object()

# ---------------------------------------------------------------------------
# Paths — resolved relative to this file's location
# ---------------------------------------------------------------------------
_SSLOPENCRYPT_DIR  = Path(__file__).resolve().parent.parent.parent
_LO_INSTALLER      = _SSLOPENCRYPT_DIR / "integrations" / "libreoffice" / "install_libreoffice.py"
_LO_IPC_SERVER     = _SSLOPENCRYPT_DIR / "integrations" / "libreoffice" / "ipc_server.py"
_DOLPHIN_INSTALLER = _SSLOPENCRYPT_DIR / "integrations" / "dolphin" / "install.sh"
_NAUTILUS_SRC      = _SSLOPENCRYPT_DIR / "integrations" / "nautilus" / "sslopencrypt-nautilus.py"
_NAUTILUS_INST_SH  = _SSLOPENCRYPT_DIR / "integrations" / "nautilus" / "install.sh"

_LO_MACRO_DEST  = Path.home() / ".config" / "libreoffice" / "4" / "user" / "Scripts" / "basic" / "sslOpenCrypt"
_DOLPHIN_DEST   = Path.home() / ".local" / "share" / "kio" / "servicemenus" / "sslopencrypt.desktop"
_NAUTILUS_DEST  = Path.home() / ".local" / "share" / "nautilus-python" / "extensions" / "sslopencrypt-nautilus.py"

_IPC_HOST = "127.0.0.1"
_IPC_PORT  = 47251


# ---------------------------------------------------------------------------
# Worker — runs a subprocess command and emits (returncode, output)
# ---------------------------------------------------------------------------
class _RunWorker(QObject):
    done = pyqtSignal(int, str)

    def __init__(self, cmd: list[str]):
        super().__init__()
        self._cmd = cmd

    def run(self):
        try:
            r = subprocess.run(
                self._cmd, capture_output=True, text=True, timeout=90,
            )
            out = (r.stdout + ("\n" + r.stderr if r.stderr.strip() else "")).strip()
            self.done.emit(r.returncode, out)
        except Exception as e:
            self.done.emit(-1, str(e))


# ---------------------------------------------------------------------------
# IntegrationsPanel
# ---------------------------------------------------------------------------
class IntegrationsPanel(BasePanel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._ipc_process: QProcess | None = None
        # Keeps strong Python refs to (thread, worker) pairs so the GC
        # does not collect worker objects before their done signal fires.
        self._active_jobs: list[tuple[QThread, _RunWorker]] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        title = QLabel("🔗  Desktop Integrations")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #F9FAFB;")
        layout.addWidget(title)

        desc = QLabel(
            "Install sslOpenCrypt into LibreOffice, Dolphin, and Nautilus — "
            "no manual configuration needed."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #9CA3AF; font-size: 11px;")
        layout.addWidget(desc)

        tabs = QTabWidget()
        tabs.addTab(self._build_lo_tab(),      "LibreOffice")
        tabs.addTab(self._build_dolphin_tab(), "Dolphin (KDE)")
        tabs.addTab(self._build_nautilus_tab(),"Nautilus / Nemo")
        layout.addWidget(tabs, stretch=1)

    # ------------------------------------------------------------------
    # LibreOffice tab
    # ------------------------------------------------------------------

    def _build_lo_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setSpacing(10)

        # Status + install group
        grp = QGroupBox("Macro Library & Keyboard Shortcuts")
        grp.setStyleSheet("QGroupBox { color: #D1D5DB; border: 1px solid #374151; border-radius: 4px; margin-top: 8px; padding-top: 8px; }")
        gl = QVBoxLayout(grp)

        info = QLabel(
            "Installs the sslOpenCrypt macro library to your LibreOffice profile and "
            "registers four global keyboard shortcuts:\n"
            "   Ctrl+Alt+S  Sign    •  Ctrl+Alt+E  Encrypt\n"
            "   Ctrl+Alt+H  Hash   •  Ctrl+Alt+V  Verify\n\n"
            "Also creates an sslOpenCrypt toolbar with icon buttons.\n"
            "Enable it via  View → Toolbars → sslOpenCrypt."
        )
        info.setStyleSheet("color: #9CA3AF; font-size: 10pt;")
        info.setWordWrap(True)
        gl.addWidget(info)

        row = QHBoxLayout()
        self._lo_status = QLabel()
        self._lo_status.setStyleSheet("font-weight: bold; font-size: 10pt;")
        row.addWidget(self._lo_status)
        row.addStretch()

        self._lo_install_btn   = QPushButton("Install LibreOffice Integration")
        self._lo_uninstall_btn = QPushButton("Uninstall")
        self._lo_uninstall_btn.setStyleSheet("QPushButton { background: #7F1D1D; } QPushButton:hover { background: #991B1B; }")
        row.addWidget(self._lo_install_btn)
        row.addWidget(self._lo_uninstall_btn)
        gl.addLayout(row)
        v.addWidget(grp)

        # IPC server group
        ipc_grp = QGroupBox("IPC Server  (required for shortcuts to work at runtime)")
        ipc_grp.setStyleSheet("QGroupBox { color: #D1D5DB; border: 1px solid #374151; border-radius: 4px; margin-top: 8px; padding-top: 8px; }")
        il = QVBoxLayout(ipc_grp)

        ipc_info = QLabel(
            "The IPC server (localhost:47251) receives requests from LibreOffice macros\n"
            "and calls the sslOpenCrypt cryptographic modules. It must be running\n"
            "whenever you want to use the shortcuts inside LibreOffice."
        )
        ipc_info.setStyleSheet("color: #9CA3AF; font-size: 10pt;")
        ipc_info.setWordWrap(True)
        il.addWidget(ipc_info)

        ipc_row = QHBoxLayout()
        self._ipc_status = QLabel()
        self._ipc_status.setStyleSheet("font-weight: bold; font-size: 10pt;")
        ipc_row.addWidget(self._ipc_status)
        ipc_row.addStretch()

        self._ipc_start_btn = QPushButton("Start IPC Server")
        self._ipc_stop_btn  = QPushButton("Stop IPC Server")
        self._ipc_stop_btn.setStyleSheet("QPushButton { background: #7F1D1D; } QPushButton:hover { background: #991B1B; }")
        ipc_row.addWidget(self._ipc_start_btn)
        ipc_row.addWidget(self._ipc_stop_btn)
        il.addLayout(ipc_row)
        v.addWidget(ipc_grp)

        # Output log
        self._lo_log = self._make_log()
        v.addWidget(QLabel("Output:"))
        v.addWidget(self._lo_log, stretch=1)

        # Wire signals
        self._lo_install_btn.clicked.connect(self._lo_install)
        self._lo_uninstall_btn.clicked.connect(self._lo_uninstall)
        self._ipc_start_btn.clicked.connect(self._ipc_start)
        self._ipc_stop_btn.clicked.connect(self._ipc_stop)

        self._refresh_lo_status()
        self._refresh_ipc_status()
        return w

    # ------------------------------------------------------------------
    # Dolphin tab
    # ------------------------------------------------------------------

    def _build_dolphin_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setSpacing(10)

        grp = QGroupBox("Dolphin / Konqueror Service Menu")
        grp.setStyleSheet("QGroupBox { color: #D1D5DB; border: 1px solid #374151; border-radius: 4px; margin-top: 8px; padding-top: 8px; }")
        gl = QVBoxLayout(grp)

        info = QLabel(
            "Adds an sslOpenCrypt submenu to Dolphin and Konqueror right-click menus:\n"
            "   Sign File…   •   Verify Signature…   •   Encrypt…\n"
            "   Decrypt…     •   Compute SHA-256…\n\n"
            "After installing, right-click any file in Dolphin to see the menu."
        )
        info.setStyleSheet("color: #9CA3AF; font-size: 10pt;")
        info.setWordWrap(True)
        gl.addWidget(info)

        row = QHBoxLayout()
        self._dolphin_status = QLabel()
        self._dolphin_status.setStyleSheet("font-weight: bold; font-size: 10pt;")
        row.addWidget(self._dolphin_status)
        row.addStretch()

        self._dolphin_install_btn   = QPushButton("Install Dolphin Integration")
        self._dolphin_uninstall_btn = QPushButton("Uninstall")
        self._dolphin_uninstall_btn.setStyleSheet("QPushButton { background: #7F1D1D; } QPushButton:hover { background: #991B1B; }")
        row.addWidget(self._dolphin_install_btn)
        row.addWidget(self._dolphin_uninstall_btn)
        gl.addLayout(row)
        v.addWidget(grp)

        self._dolphin_log = self._make_log()
        v.addWidget(QLabel("Output:"))
        v.addWidget(self._dolphin_log, stretch=1)

        self._dolphin_install_btn.clicked.connect(self._dolphin_install)
        self._dolphin_uninstall_btn.clicked.connect(self._dolphin_uninstall)

        self._refresh_dolphin_status()
        return w

    # ------------------------------------------------------------------
    # Nautilus tab
    # ------------------------------------------------------------------

    def _build_nautilus_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.setSpacing(10)

        grp = QGroupBox("Nautilus (GNOME) / Nemo (Cinnamon) Extension")
        grp.setStyleSheet("QGroupBox { color: #D1D5DB; border: 1px solid #374151; border-radius: 4px; margin-top: 8px; padding-top: 8px; }")
        gl = QVBoxLayout(grp)

        info = QLabel(
            "Adds an sslOpenCrypt submenu to Nautilus and Nemo right-click menus:\n"
            "   Encrypt…   •   Decrypt…   •   Sign…\n"
            "   Verify Signature…   •   Compute SHA-256…\n\n"
            "Requires: python3-nautilus (sudo apt install python3-nautilus)\n"
            "After installing, restart Nautilus for the extension to load."
        )
        info.setStyleSheet("color: #9CA3AF; font-size: 10pt;")
        info.setWordWrap(True)
        gl.addWidget(info)

        row = QHBoxLayout()
        self._nautilus_status = QLabel()
        self._nautilus_status.setStyleSheet("font-weight: bold; font-size: 10pt;")
        row.addWidget(self._nautilus_status)
        row.addStretch()

        self._nautilus_install_btn   = QPushButton("Install Nautilus Extension")
        self._nautilus_uninstall_btn = QPushButton("Uninstall")
        self._nautilus_uninstall_btn.setStyleSheet("QPushButton { background: #7F1D1D; } QPushButton:hover { background: #991B1B; }")
        row.addWidget(self._nautilus_install_btn)
        row.addWidget(self._nautilus_uninstall_btn)
        gl.addLayout(row)
        v.addWidget(grp)

        self._nautilus_log = self._make_log()
        v.addWidget(QLabel("Output:"))
        v.addWidget(self._nautilus_log, stretch=1)

        self._nautilus_install_btn.clicked.connect(self._nautilus_install)
        self._nautilus_uninstall_btn.clicked.connect(self._nautilus_uninstall)

        self._refresh_nautilus_status()
        return w

    # ------------------------------------------------------------------
    # Status refreshers
    # ------------------------------------------------------------------

    def _refresh_lo_status(self):
        if _LO_MACRO_DEST.is_dir():
            self._lo_status.setText("✅  Installed")
            self._lo_status.setStyleSheet("color: #34D399; font-weight: bold;")
        else:
            self._lo_status.setText("❌  Not installed")
            self._lo_status.setStyleSheet("color: #F87171; font-weight: bold;")

    def _refresh_ipc_status(self):
        running = self._ipc_is_running()
        if running:
            self._ipc_status.setText(f"🟢  Running on {_IPC_HOST}:{_IPC_PORT}")
            self._ipc_status.setStyleSheet("color: #34D399; font-weight: bold;")
        else:
            self._ipc_status.setText("🔴  Not running")
            self._ipc_status.setStyleSheet("color: #F87171; font-weight: bold;")
        self._ipc_start_btn.setEnabled(not running)
        self._ipc_stop_btn.setEnabled(running)

    def _refresh_dolphin_status(self):
        if _DOLPHIN_DEST.exists():
            self._dolphin_status.setText("✅  Installed")
            self._dolphin_status.setStyleSheet("color: #34D399; font-weight: bold;")
        else:
            self._dolphin_status.setText("❌  Not installed")
            self._dolphin_status.setStyleSheet("color: #F87171; font-weight: bold;")

    def _refresh_nautilus_status(self):
        if _NAUTILUS_DEST.exists():
            self._nautilus_status.setText("✅  Installed")
            self._nautilus_status.setStyleSheet("color: #34D399; font-weight: bold;")
        else:
            self._nautilus_status.setText("❌  Not installed")
            self._nautilus_status.setStyleSheet("color: #F87171; font-weight: bold;")

    # ------------------------------------------------------------------
    # LibreOffice install / uninstall
    # ------------------------------------------------------------------

    def _lo_install(self):
        self._lo_log.clear()
        self._lo_log.append("Running LibreOffice installer…\n")
        self._lo_install_btn.setEnabled(False)
        self._lo_install_btn.setText("Installing…")
        if not _LO_INSTALLER.exists():
            self._lo_log.append(f"⚠️  Installer not found:\n    {_LO_INSTALLER}")
            self._lo_install_btn.setEnabled(True)
            self._lo_install_btn.setText("Install LibreOffice Integration")
            return
        self._run_cmd(
            [sys.executable, str(_LO_INSTALLER)],
            on_done=self._lo_install_done,
        )

    def _lo_install_done(self, rc: int, out: str):
        if out:
            self._lo_log.append(out)
        if rc == 0:
            self._lo_log.append("\n✅  Installation complete.")
        else:
            self._lo_log.append(f"\n⚠️  Installer exited with code {rc}.")
        self._lo_install_btn.setEnabled(True)
        self._lo_install_btn.setText("Install LibreOffice Integration")
        self._refresh_lo_status()

    def _lo_uninstall(self):
        self._lo_log.clear()
        self._lo_log.append("Removing LibreOffice macro library…\n")
        self._run_cmd(
            [sys.executable, str(_LO_INSTALLER), "--remove"],
            on_done=self._lo_uninstall_done,
        )

    def _lo_uninstall_done(self, rc: int, out: str):
        if out:
            self._lo_log.append(out)
        self._lo_log.append("\n✅  Uninstalled." if rc == 0 else f"\n⚠️  Exit {rc}.")
        self._refresh_lo_status()

    # ------------------------------------------------------------------
    # IPC server start / stop
    # ------------------------------------------------------------------

    def _ipc_is_running(self) -> bool:
        try:
            with socket.create_connection((_IPC_HOST, _IPC_PORT), timeout=0.5):
                return True
        except OSError:
            return False

    def _ipc_start(self):
        if self._ipc_process and self._ipc_process.state() == QProcess.ProcessState.Running:
            return
        self._ipc_process = QProcess(self)
        self._ipc_process.setProgram(sys.executable)
        self._ipc_process.setArguments([str(_LO_IPC_SERVER)])
        self._ipc_process.readyReadStandardOutput.connect(self._ipc_on_stdout)
        self._ipc_process.readyReadStandardError.connect(self._ipc_on_stderr)
        self._ipc_process.started.connect(self._refresh_ipc_status)
        self._ipc_process.finished.connect(self._refresh_ipc_status)
        self._ipc_process.start()
        self._lo_log.append("▶  IPC server starting…")

    def _ipc_stop(self):
        if self._ipc_process:
            self._ipc_process.terminate()
            if not self._ipc_process.waitForFinished(2000):
                self._ipc_process.kill()
            self._lo_log.append("■  IPC server stopped.")
        self._refresh_ipc_status()

    def _ipc_on_stdout(self):
        if self._ipc_process:
            data = bytes(self._ipc_process.readAllStandardOutput()).decode(errors="replace")
            self._lo_log.append(data.strip())

    def _ipc_on_stderr(self):
        if self._ipc_process:
            data = bytes(self._ipc_process.readAllStandardError()).decode(errors="replace")
            self._lo_log.append(data.strip())

    # ------------------------------------------------------------------
    # Dolphin install / uninstall
    # ------------------------------------------------------------------

    def _dolphin_install(self):
        self._dolphin_log.clear()
        self._dolphin_log.append("Running Dolphin installer…\n")
        self._dolphin_install_btn.setEnabled(False)
        self._dolphin_install_btn.setText("Installing…")
        if not _DOLPHIN_INSTALLER.exists():
            self._dolphin_log.append(f"⚠️  Installer not found:\n    {_DOLPHIN_INSTALLER}")
            self._dolphin_install_btn.setEnabled(True)
            self._dolphin_install_btn.setText("Install Dolphin Integration")
            return
        self._run_cmd(
            ["bash", str(_DOLPHIN_INSTALLER)],
            on_done=self._dolphin_install_done,
        )

    def _dolphin_install_done(self, rc: int, out: str):
        if out:
            self._dolphin_log.append(out)
        self._dolphin_log.append("\n✅  Done." if rc == 0 else f"\n⚠️  Exit {rc}.")
        self._dolphin_install_btn.setEnabled(True)
        self._dolphin_install_btn.setText("Install Dolphin Integration")
        self._refresh_dolphin_status()

    def _dolphin_uninstall(self):
        self._dolphin_log.clear()
        self._dolphin_log.append("Removing Dolphin service menu…\n")
        self._run_cmd(
            ["bash", str(_DOLPHIN_INSTALLER), "--remove"],
            on_done=self._dolphin_uninstall_done,
        )

    def _dolphin_uninstall_done(self, rc: int, out: str):
        if out:
            self._dolphin_log.append(out)
        self._dolphin_log.append("\n✅  Done." if rc == 0 else f"\n⚠️  Exit {rc}.")
        self._refresh_dolphin_status()

    # ------------------------------------------------------------------
    # Nautilus install / uninstall
    # ------------------------------------------------------------------

    def _nautilus_install(self):
        self._nautilus_log.clear()
        self._nautilus_log.append("Installing Nautilus extension…\n")
        self._nautilus_install_btn.setEnabled(False)
        self._nautilus_install_btn.setText("Installing…")
        if not _NAUTILUS_INST_SH.exists():
            self._nautilus_log.append(f"⚠️  Installer not found:\n    {_NAUTILUS_INST_SH}")
            self._nautilus_install_btn.setEnabled(True)
            self._nautilus_install_btn.setText("Install Nautilus Extension")
            return
        self._run_cmd(
            ["bash", str(_NAUTILUS_INST_SH)],
            on_done=self._nautilus_install_done,
        )

    def _nautilus_install_done(self, rc: int, out: str):
        if out:
            self._nautilus_log.append(out)
        self._nautilus_log.append("\n✅  Done." if rc == 0 else f"\n⚠️  Exit {rc}.")
        self._nautilus_install_btn.setEnabled(True)
        self._nautilus_install_btn.setText("Install Nautilus Extension")
        self._refresh_nautilus_status()

    def _nautilus_uninstall(self):
        self._nautilus_log.clear()
        self._nautilus_log.append("Removing Nautilus extension…\n")
        self._run_cmd(
            ["bash", str(_NAUTILUS_INST_SH), "--remove"],
            on_done=self._nautilus_uninstall_done,
        )

    def _nautilus_uninstall_done(self, rc: int, out: str):
        if out:
            self._nautilus_log.append(out)
        self._nautilus_log.append("\n✅  Done." if rc == 0 else f"\n⚠️  Exit {rc}.")
        self._refresh_nautilus_status()

    # ------------------------------------------------------------------
    # Generic subprocess runner (non-blocking via QThread)
    # ------------------------------------------------------------------

    def _run_cmd(self, cmd: list[str], on_done):
        worker = _RunWorker(cmd)
        thread = QThread(self)
        worker.moveToThread(thread)

        # Keep strong Python references to both objects.  PyQt6 only holds
        # weak references for signal-to-bound-method connections, so without
        # this the worker can be GC'd before its done signal ever fires.
        job = (thread, worker)
        self._active_jobs.append(job)

        def _cleanup():
            try:
                self._active_jobs.remove(job)
            except ValueError:
                pass

        thread.started.connect(worker.run)
        worker.done.connect(on_done)
        worker.done.connect(thread.quit)
        thread.finished.connect(_cleanup)
        thread.finished.connect(thread.deleteLater)
        worker.done.connect(worker.deleteLater)
        thread.start()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_log() -> QTextEdit:
        t = QTextEdit()
        t.setReadOnly(True)
        t.setStyleSheet(
            "background: #0D1117; color: #C9D1D9; font-family: monospace; "
            "font-size: 9pt; border: 1px solid #374151; border-radius: 4px;"
        )
        t.setMinimumHeight(120)
        return t
