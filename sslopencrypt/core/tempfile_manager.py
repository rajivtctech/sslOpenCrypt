"""
core/tempfile_manager.py — Secure temporary file management.

Spec requirement:
  - Private keys are NEVER written to /tmp or any unprotected path.
  - All temp files use tempfile.mkstemp() with mode 0o600.
  - Files are securely deleted (overwritten with zeros) after use.
"""

import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path


class SecureTempFile:
    """A temporary file with mode 0o600 that overwrites its content on deletion."""

    def __init__(self, suffix: str = "", prefix: str = "ssl_", dir: str | None = None):
        fd, self.path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
        os.close(fd)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    def write(self, data: bytes | str) -> None:
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(self.path, mode) as f:
            f.write(data)

    def read(self) -> bytes:
        with open(self.path, "rb") as f:
            return f.read()

    def read_text(self) -> str:
        with open(self.path, "r") as f:
            return f.read()

    def secure_delete(self) -> None:
        """Overwrite with zeros then unlink."""
        try:
            size = os.path.getsize(self.path)
            with open(self.path, "wb") as f:
                f.write(b"\x00" * size)
            os.unlink(self.path)
        except OSError:
            try:
                os.unlink(self.path)
            except OSError:
                pass

    def __del__(self):
        if os.path.exists(self.path):
            self.secure_delete()


@contextmanager
def secure_temp_file(suffix: str = "", prefix: str = "ssl_", content: bytes | str | None = None):
    """Context manager yielding a SecureTempFile that is deleted on exit."""
    tf = SecureTempFile(suffix=suffix, prefix=prefix)
    try:
        if content is not None:
            tf.write(content)
        yield tf
    finally:
        tf.secure_delete()


@contextmanager
def secure_temp_dir():
    """Context manager yielding a temporary directory that is cleaned up on exit."""
    import shutil
    d = tempfile.mkdtemp(prefix="ssl_")
    os.chmod(d, stat.S_IRWXU)
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)
