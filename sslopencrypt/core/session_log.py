"""
core/session_log.py — In-session operation log for Classroom Mode.

Records every cryptographic operation performed during the current GUI session.
Used to generate lab reports and enforce Classroom Mode session logging.

The session log is in-memory only; persisted to a file only when the user
explicitly exports a lab report.

Each entry:
  {
    "seq":        int (1-based sequence number),
    "ts":         str (ISO-8601 UTC),
    "module":     str,
    "operation":  str,
    "command":    str (display-safe),
    "success":    bool,
    "note":       str (optional user annotation),
    "deprecated": bool,
    "deprecated_alg": str,
  }
"""

from datetime import datetime, timezone
from typing import Callable


_entries: list[dict] = []
_session_start: datetime | None = None
_student_name: str = ""
_session_title: str = ""
_listeners: list[Callable] = []


def start_session(student_name: str = "", session_title: str = "") -> None:
    """Start a new session (clears previous entries)."""
    global _entries, _session_start, _student_name, _session_title
    _entries = []
    _session_start = datetime.now(timezone.utc)
    _student_name = student_name.strip()
    _session_title = session_title.strip() or "Cryptography Lab Session"


def log_entry(
    module: str,
    operation: str,
    command: str,
    success: bool,
    deprecated: bool = False,
    deprecated_alg: str = "",
    note: str = "",
) -> None:
    """Append an operation to the session log."""
    if _session_start is None:
        return  # not in classroom session
    entry = {
        "seq":            len(_entries) + 1,
        "ts":             datetime.now(timezone.utc).isoformat(),
        "module":         module,
        "operation":      operation,
        "command":        command,
        "success":        success,
        "note":           note,
        "deprecated":     deprecated,
        "deprecated_alg": deprecated_alg,
    }
    _entries.append(entry)
    for cb in _listeners:
        try:
            cb(entry)
        except Exception:
            pass


def get_entries() -> list[dict]:
    return list(_entries)


def get_session_info() -> dict:
    return {
        "student_name":  _student_name,
        "session_title": _session_title,
        "start_time":    _session_start.isoformat() if _session_start else "",
        "total_ops":     len(_entries),
        "successes":     sum(1 for e in _entries if e["success"]),
        "failures":      sum(1 for e in _entries if not e["success"]),
        "deprecated_used": sum(1 for e in _entries if e["deprecated"]),
    }


def is_active() -> bool:
    """Returns True if a classroom session is active."""
    return _session_start is not None


def add_listener(callback: Callable) -> None:
    """Register a callback(entry) called whenever a new entry is logged."""
    _listeners.append(callback)


def remove_listener(callback: Callable) -> None:
    if callback in _listeners:
        _listeners.remove(callback)


def clear() -> None:
    """Clear session without stopping it (useful for reset during tests)."""
    global _entries
    _entries = []


def stop_session() -> None:
    """End the classroom session."""
    global _entries, _session_start, _student_name, _session_title
    _entries = []
    _session_start = None
    _student_name = ""
    _session_title = ""
