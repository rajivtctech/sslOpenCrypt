"""
ui/command_console.py — The Command Console widget.

The signature feature of sslOpenCrypt: shows the exact openssl/gpg commands
run by every GUI action, syntax-highlighted, with copy/bookmark/export buttons.

In Expert Mode: the console is visible and commands can be edited + re-run.
In Beginner Mode: the console is hidden.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget,
    QFileDialog, QMessageBox,
)

from core.result import ExecutionResult


# ---------------------------------------------------------------------------
# Syntax highlighter for openssl commands
# ---------------------------------------------------------------------------

class OpenSSLHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self._rules = []

        # Comment / warning lines (# ...)
        fmt_comment = QTextCharFormat()
        fmt_comment.setForeground(QColor("#F59E0B"))  # Amber
        fmt_comment.setFontItalic(True)
        self._rules.append(("^#.*$", fmt_comment))

        # openssl / gpg binary name
        fmt_bin = QTextCharFormat()
        fmt_bin.setForeground(QColor("#34D399"))  # Green
        fmt_bin.setFontWeight(700)
        self._rules.append((r"^(openssl|gpg2?)\b", fmt_bin))

        # Subcommand (second word)
        fmt_sub = QTextCharFormat()
        fmt_sub.setForeground(QColor("#60A5FA"))  # Blue
        fmt_sub.setFontWeight(700)
        self._rules.append((r"(?<=openssl )\S+|(?<=gpg2? )\S+", fmt_sub))

        # Flags starting with -
        fmt_flag = QTextCharFormat()
        fmt_flag.setForeground(QColor("#A78BFA"))  # Purple
        self._rules.append((r"\s-{1,2}\w[\w\-]*", fmt_flag))

        # [PASSPHRASE] placeholder
        fmt_pass = QTextCharFormat()
        fmt_pass.setForeground(QColor("#F87171"))  # Red
        fmt_pass.setFontWeight(700)
        self._rules.append((r"\[PASSPHRASE\]", fmt_pass))

        # String values in quotes
        fmt_str = QTextCharFormat()
        fmt_str.setForeground(QColor("#FCD34D"))  # Yellow
        self._rules.append((r'"[^"]*"', fmt_str))

    def highlightBlock(self, text: str):
        import re
        for pattern, fmt in self._rules:
            for m in re.finditer(pattern, text, re.MULTILINE):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ---------------------------------------------------------------------------
# Console Widget
# ---------------------------------------------------------------------------

class CommandConsole(QWidget):
    """
    Bottom panel showing real-time openssl commands.
    Signal re_run_requested emits the edited command string if user clicks Re-run.
    """
    re_run_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._session_commands: list[str] = []
        self._bookmarks: list[str] = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header bar
        header = QHBoxLayout()
        title = QLabel("Command Console")
        title.setStyleSheet("font-weight: bold; color: #9CA3AF;")
        header.addWidget(title)
        header.addStretch()

        self._btn_copy = QPushButton("Copy")
        self._btn_copy.setToolTip("Copy all commands to clipboard")
        self._btn_copy.setMaximumWidth(60)
        self._btn_copy.clicked.connect(self._copy_all)

        self._btn_bookmark = QPushButton("Bookmark")
        self._btn_bookmark.setToolTip("Bookmark the last command")
        self._btn_bookmark.setMaximumWidth(80)
        self._btn_bookmark.clicked.connect(self._bookmark_last)

        self._btn_export = QPushButton("Export .sh")
        self._btn_export.setToolTip("Export session as a shell script")
        self._btn_export.setMaximumWidth(80)
        self._btn_export.clicked.connect(self._export_script)

        self._btn_clear = QPushButton("Clear")
        self._btn_clear.setMaximumWidth(55)
        self._btn_clear.clicked.connect(self._clear)

        for btn in [self._btn_copy, self._btn_bookmark, self._btn_export, self._btn_clear]:
            header.addWidget(btn)

        layout.addLayout(header)

        # Text area
        self._text = QTextEdit()
        self._text.setReadOnly(False)
        self._text.setFont(QFont("Monospace", 9))
        self._text.setStyleSheet(
            "background-color: #111827; color: #D1FAE5; border: 1px solid #374151;"
        )
        self._text.setMinimumHeight(100)
        self._text.setMaximumHeight(220)
        OpenSSLHighlighter(self._text.document())
        layout.addWidget(self._text)

        # Re-run button (Expert Mode only — enabled externally)
        self._btn_rerun = QPushButton("Re-run edited command")
        self._btn_rerun.setVisible(False)
        self._btn_rerun.clicked.connect(self._rerun)
        layout.addWidget(self._btn_rerun)

    def set_expert_mode(self, expert: bool):
        self._text.setReadOnly(not expert)
        self._btn_rerun.setVisible(expert)

    def append_result(self, result: ExecutionResult):
        """Add a command from an ExecutionResult to the console."""
        cmd_str = result.command_str
        if cmd_str:
            self._session_commands.append(cmd_str)
            separator = "\n" + "─" * 60 + "\n"
            current = self._text.toPlainText()
            if current:
                self._text.setPlainText(current + separator + cmd_str)
            else:
                self._text.setPlainText(cmd_str)
            # Scroll to end
            cursor = self._text.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            self._text.setTextCursor(cursor)

    def append_command(self, cmd_str: str):
        """Append a raw command string."""
        if cmd_str:
            self._session_commands.append(cmd_str)
            current = self._text.toPlainText()
            separator = "\n" + "─" * 60 + "\n"
            new_text = (current + separator + cmd_str) if current else cmd_str
            self._text.setPlainText(new_text)

    def _copy_all(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self._text.toPlainText())

    def _bookmark_last(self):
        if self._session_commands:
            self._bookmarks.append(self._session_commands[-1])
            QMessageBox.information(self, "Bookmarked", "Last command bookmarked.")

    def _export_script(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Shell Script", "", "Shell Scripts (*.sh);;Batch Files (*.bat);;All Files (*)"
        )
        if path:
            content = "#!/bin/bash\n# sslOpenCrypt session export\n\n"
            content += "\n\n".join(self._session_commands)
            with open(path, "w") as f:
                f.write(content)
            QMessageBox.information(self, "Exported", f"Session saved to {path}")

    def _clear(self):
        self._text.clear()
        self._session_commands.clear()

    def _rerun(self):
        cmd = self._text.toPlainText().strip()
        if cmd:
            self.re_run_requested.emit(cmd)
