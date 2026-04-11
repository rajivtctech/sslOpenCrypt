"""
core/audit_log.py — Immutable local audit log.

Every cryptographic operation is logged with:
  - ISO-8601 timestamp
  - module name
  - operation description
  - command string (display-safe, passphrase masked)
  - success/failure
  - DEPRECATED_ALG flag when applicable

The log is append-only (O_WRONLY | O_APPEND | O_CREAT).
It is stored at ~/.sslopencrypt/audit.log (newline-delimited JSON).
"""

import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


def _log_path() -> Path:
    base = Path.home() / ".sslopencrypt"
    base.mkdir(mode=0o700, exist_ok=True)
    return base / "audit.log"


def _log_dir() -> Path:
    return Path.home() / ".sslopencrypt"


def log_operation(
    module: str,
    operation: str,
    command_str: str,
    success: bool,
    is_deprecated: bool = False,
    deprecated_alg: str = "",
    extra: dict | None = None,
) -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "module": module,
        "operation": operation,
        "command": command_str,
        "success": success,
    }
    if is_deprecated:
        entry["flag"] = "DEPRECATED_ALG"
        entry["alg"] = deprecated_alg
    if extra:
        entry.update(extra)

    path = _log_path()
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        f.write(line)

    # Mirror to classroom session log (no-op when session inactive)
    try:
        from core.session_log import log_entry, is_active
        if is_active():
            log_entry(
                module=module,
                operation=operation,
                command=command_str,
                success=success,
                deprecated=is_deprecated,
                deprecated_alg=deprecated_alg,
            )
    except ImportError:
        pass


def read_log(max_entries: int = 1000) -> list[dict]:
    path = _log_path()
    if not path.exists():
        return []
    entries = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries[-max_entries:]


def export_log(dest_path: str) -> None:
    """Export audit log to a file (for compliance evidence)."""
    entries = read_log(max_entries=100000)
    with open(dest_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)
