"""
ui/panels/base_panel.py — Base class for all module panels.

Provides:
  - result_ready signal with ExecutionResult
  - deprecated_warning handling (amber border + confirmation checkbox)
  - run_in_thread helper for async subprocess calls
  - standard output/status display
"""

from PyQt6.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox, QFrame, QLabel, QProgressBar,
    QTextEdit, QVBoxLayout, QWidget, QHBoxLayout,
    QSizePolicy,
)

from core.result import ExecutionResult


class _Worker(QObject):
    finished = pyqtSignal(object)  # ExecutionResult

    def __init__(self, func, args, kwargs):
        super().__init__()
        self._func = func
        self._args = args
        self._kwargs = kwargs

    def run(self):
        try:
            result = self._func(*self._args, **self._kwargs)
        except Exception as e:
            result = ExecutionResult(
                command=[], command_str="",
                stdout="", stderr=str(e),
                parsed={}, success=False, exit_code=-1,
            )
        self.finished.emit(result)


class BasePanel(QWidget):
    """Base class for all module panels."""

    result_ready = pyqtSignal(object)   # ExecutionResult

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: _Worker | None = None   # keep reference to prevent GC
        self._deprecated_confirmed = False

    # ------------------------------------------------------------------
    # Async execution helper
    # ------------------------------------------------------------------

    def run_in_thread(self, func, *args, callback=None, **kwargs):
        """
        Run func(*args, **kwargs) in a worker thread.

        On completion, always emits result_ready (for the Command Console).
        If callback is provided, it is called with the ExecutionResult in
        addition to result_ready — use this instead of connecting result_ready
        manually (avoids race conditions and double-connection bugs).
        """
        if self._thread and self._thread.isRunning():
            return  # Already busy

        # Store worker on self so Python's GC does not collect it before the
        # thread finishes and the finished signal is delivered.
        self._worker = _Worker(func, args, kwargs)
        self._pending_callback = callback

        thread = QThread()
        self._worker.moveToThread(thread)
        thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_thread_done)
        self._worker.finished.connect(thread.quit)
        thread.finished.connect(thread.deleteLater)
        self._thread = thread
        thread.start()

    def _on_thread_done(self, result: ExecutionResult):
        # Always emit for the Command Console wired up in main_window
        self.result_ready.emit(result)
        # Call the per-operation callback if one was registered
        cb = getattr(self, "_pending_callback", None)
        if cb is not None:
            self._pending_callback = None
            cb(result)
        # Release worker reference
        self._worker = None

    # ------------------------------------------------------------------
    # Deprecated algorithm guardrails
    # ------------------------------------------------------------------

    def build_deprecated_warning_widget(self, alg_name: str) -> tuple[QWidget, QCheckBox]:
        """
        Build the amber warning banner + confirmation checkbox required by the spec.
        Returns (widget, checkbox). Parent must keep reference.
        """
        container = QWidget()
        container.setStyleSheet(
            "background-color: #451A03; border: 2px solid #F59E0B; border-radius: 6px; padding: 4px;"
        )
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        title = QLabel(f"⚠  WARNING — {alg_name} is DEPRECATED")
        title.setStyleSheet("color: #FCD34D; font-weight: bold; font-size: 11px;")
        layout.addWidget(title)

        from core.result import DEPRECATED_ALGORITHMS
        msg = DEPRECATED_ALGORITHMS.get(alg_name.lower(), "This algorithm is considered insecure.")
        body = QLabel(msg)
        body.setWordWrap(True)
        body.setStyleSheet("color: #FDE68A; font-size: 10px;")
        layout.addWidget(body)

        console_note = QLabel(
            "# WARNING annotation will be prepended to the console command."
        )
        console_note.setStyleSheet("color: #9CA3AF; font-size: 9px; font-style: italic;")
        layout.addWidget(console_note)

        cb = QCheckBox("I understand this algorithm is deprecated and I accept the associated risk")
        cb.setStyleSheet("color: #FDE68A; font-size: 10px;")
        layout.addWidget(cb)

        return container, cb

    # ------------------------------------------------------------------
    # Standard output display
    # ------------------------------------------------------------------

    def build_output_area(self, label: str = "Output") -> tuple[QWidget, QTextEdit]:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 4, 0, 0)
        lbl = QLabel(label)
        lbl.setStyleSheet("color: #9CA3AF; font-size: 10px;")
        layout.addWidget(lbl)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setFont(QFont("Monospace", 9))
        text.setStyleSheet(
            "background:#111827; color:#D1FAE5; border:1px solid #374151; border-radius:4px;"
        )
        layout.addWidget(text)
        return container, text

    def build_status_label(self) -> QLabel:
        lbl = QLabel()
        lbl.setWordWrap(True)
        lbl.setStyleSheet("font-size: 11px; padding: 4px;")
        return lbl

    def show_result(self, result: ExecutionResult, output_text: QTextEdit, status_label: QLabel):
        """Standard result display: output text + coloured status label."""
        output_text.setPlainText(result.output or result.stdout or result.stderr)
        if result.success:
            status_label.setText("✓  Success")
            status_label.setStyleSheet("color: #34D399; font-weight: bold; font-size: 11px;")
        else:
            status_label.setText(f"✗  Failed: {result.error_message[:200]}")
            status_label.setStyleSheet("color: #F87171; font-weight: bold; font-size: 11px;")
