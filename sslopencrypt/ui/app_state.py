"""
ui/app_state.py — Global application state and mode management.

Modes:
  - BEGINNER: Command Console hidden, simplified labels, safe defaults only
  - EXPERT:   Console visible and editable, all algorithms exposed
  - CLASSROOM: Expert + instructor constraints + forced session log
  - BATCH_CLI: Headless — not used by the GUI
"""

from enum import Enum
from PyQt6.QtCore import QObject, pyqtSignal


class AppMode(Enum):
    BEGINNER = "beginner"
    EXPERT = "expert"
    CLASSROOM = "classroom"


class AppState(QObject):
    """Singleton application state. Emit signals on mode change."""

    mode_changed = pyqtSignal(AppMode)
    openssl_version_ready = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self._mode = AppMode.BEGINNER
        self._openssl_version = ""

    @property
    def mode(self) -> AppMode:
        return self._mode

    @mode.setter
    def mode(self, new_mode: AppMode):
        if new_mode != self._mode:
            self._mode = new_mode
            self.mode_changed.emit(new_mode)

    @property
    def is_expert(self) -> bool:
        return self._mode in (AppMode.EXPERT, AppMode.CLASSROOM)

    @property
    def openssl_version(self) -> str:
        return self._openssl_version

    @openssl_version.setter
    def openssl_version(self, v: str):
        self._openssl_version = v
        self.openssl_version_ready.emit(v)


# Global singleton
app_state = AppState()
