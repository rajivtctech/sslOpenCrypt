"""
tests/test_session_log.py — Tests for core/session_log.py and core/lab_report.py
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_session():
    """Ensure a clean session state before and after each test."""
    from core import session_log
    session_log.stop_session()
    yield
    session_log.stop_session()


# ---------------------------------------------------------------------------
# TestSessionLifecycle
# ---------------------------------------------------------------------------

class TestSessionLifecycle:
    def test_initially_inactive(self):
        from core.session_log import is_active
        assert not is_active()

    def test_start_session_activates(self):
        from core.session_log import start_session, is_active
        start_session("Alice", "Lab 1")
        assert is_active()

    def test_stop_session_deactivates(self):
        from core.session_log import start_session, stop_session, is_active
        start_session()
        stop_session()
        assert not is_active()

    def test_start_clears_previous_entries(self):
        from core.session_log import start_session, log_entry, get_entries
        start_session("Bob")
        log_entry("hashing", "SHA-256", "openssl dgst -sha256 file", True)
        start_session("Alice")
        assert get_entries() == []

    def test_stop_clears_entries(self):
        from core.session_log import start_session, log_entry, stop_session, get_entries
        start_session()
        log_entry("hashing", "SHA-256", "cmd", True)
        stop_session()
        assert get_entries() == []

    def test_default_session_title(self):
        from core.session_log import start_session, get_session_info
        start_session("Eve")
        info = get_session_info()
        assert info["session_title"] == "Cryptography Lab Session"

    def test_custom_session_title(self):
        from core.session_log import start_session, get_session_info
        start_session("Eve", "Advanced PKI Lab")
        info = get_session_info()
        assert info["session_title"] == "Advanced PKI Lab"


# ---------------------------------------------------------------------------
# TestLogEntry
# ---------------------------------------------------------------------------

class TestLogEntry:
    def test_log_entry_adds_record(self):
        from core.session_log import start_session, log_entry, get_entries
        start_session()
        log_entry("hashing", "SHA-256 hash", "openssl dgst -sha256 test.txt", True)
        entries = get_entries()
        assert len(entries) == 1

    def test_entry_fields(self):
        from core.session_log import start_session, log_entry, get_entries
        start_session()
        log_entry("symmetric", "AES-256-GCM encrypt", "openssl enc -aes-256-gcm", True,
                  deprecated=False, deprecated_alg="", note="test note")
        e = get_entries()[0]
        assert e["seq"] == 1
        assert e["module"] == "symmetric"
        assert e["operation"] == "AES-256-GCM encrypt"
        assert e["command"] == "openssl enc -aes-256-gcm"
        assert e["success"] is True
        assert e["deprecated"] is False
        assert e["note"] == "test note"
        assert "ts" in e

    def test_entry_sequence_numbers(self):
        from core.session_log import start_session, log_entry, get_entries
        start_session()
        log_entry("hashing", "op1", "cmd1", True)
        log_entry("hashing", "op2", "cmd2", True)
        log_entry("hashing", "op3", "cmd3", False)
        entries = get_entries()
        assert [e["seq"] for e in entries] == [1, 2, 3]

    def test_log_entry_noop_when_inactive(self):
        from core.session_log import log_entry, get_entries, is_active
        assert not is_active()
        log_entry("hashing", "op", "cmd", True)
        assert get_entries() == []

    def test_deprecated_entry(self):
        from core.session_log import start_session, log_entry, get_entries
        start_session()
        log_entry("symmetric", "DES encrypt", "openssl enc -des", True,
                  deprecated=True, deprecated_alg="DES")
        e = get_entries()[0]
        assert e["deprecated"] is True
        assert e["deprecated_alg"] == "DES"

    def test_get_entries_returns_copy(self):
        """Mutating the returned list does not affect internal state."""
        from core.session_log import start_session, log_entry, get_entries
        start_session()
        log_entry("hashing", "op", "cmd", True)
        entries = get_entries()
        entries.clear()
        assert len(get_entries()) == 1


# ---------------------------------------------------------------------------
# TestGetSessionInfo
# ---------------------------------------------------------------------------

class TestGetSessionInfo:
    def test_session_info_counters(self):
        from core.session_log import start_session, log_entry, get_session_info
        start_session("Charlie")
        log_entry("keymgmt", "gen RSA", "cmd", True)
        log_entry("hashing", "hash", "cmd", True)
        log_entry("symmetric", "AES", "cmd", False)
        log_entry("symmetric", "DES", "cmd", True, deprecated=True, deprecated_alg="DES")
        info = get_session_info()
        assert info["total_ops"] == 4
        assert info["successes"] == 3
        assert info["failures"] == 1
        assert info["deprecated_used"] == 1
        assert info["student_name"] == "Charlie"

    def test_session_info_empty(self):
        from core.session_log import start_session, get_session_info
        start_session()
        info = get_session_info()
        assert info["total_ops"] == 0
        assert info["successes"] == 0
        assert info["failures"] == 0

    def test_start_time_is_iso(self):
        from core.session_log import start_session, get_session_info
        start_session()
        info = get_session_info()
        start = info.get("start_time", "")
        assert "T" in start  # ISO-8601 format


# ---------------------------------------------------------------------------
# TestListeners
# ---------------------------------------------------------------------------

class TestListeners:
    def test_listener_called_on_entry(self):
        from core.session_log import start_session, log_entry, add_listener, remove_listener
        received = []
        cb = lambda e: received.append(e)
        add_listener(cb)
        start_session()
        log_entry("hashing", "op", "cmd", True)
        remove_listener(cb)
        assert len(received) == 1
        assert received[0]["module"] == "hashing"

    def test_multiple_listeners(self):
        from core.session_log import start_session, log_entry, add_listener, remove_listener
        results_a, results_b = [], []
        cb_a = lambda e: results_a.append(e)
        cb_b = lambda e: results_b.append(e)
        add_listener(cb_a)
        add_listener(cb_b)
        start_session()
        log_entry("hashing", "op", "cmd", True)
        remove_listener(cb_a)
        remove_listener(cb_b)
        assert len(results_a) == 1
        assert len(results_b) == 1

    def test_listener_exception_doesnt_crash(self):
        from core.session_log import start_session, log_entry, add_listener, remove_listener
        def bad_cb(e):
            raise RuntimeError("listener error")
        add_listener(bad_cb)
        start_session()
        # Should not raise
        log_entry("hashing", "op", "cmd", True)
        remove_listener(bad_cb)


# ---------------------------------------------------------------------------
# TestClear
# ---------------------------------------------------------------------------

class TestClear:
    def test_clear_removes_entries_keeps_session(self):
        from core.session_log import start_session, log_entry, clear, get_entries, is_active
        start_session()
        log_entry("hashing", "op", "cmd", True)
        assert len(get_entries()) == 1
        clear()
        assert len(get_entries()) == 0
        assert is_active()  # session still active


# ---------------------------------------------------------------------------
# TestLabReport
# ---------------------------------------------------------------------------

class TestLabReport:
    def test_generate_html_report_basic(self):
        from core.session_log import start_session, log_entry, get_session_info, get_entries
        from core.lab_report import generate_html_report
        start_session("Diana", "PKI Lab")
        log_entry("pki", "gen cert", "openssl req -x509", True)
        log_entry("symmetric", "DES enc", "openssl enc -des", True, deprecated=True, deprecated_alg="DES")
        log_entry("hashing", "hash", "openssl dgst", False)
        html = generate_html_report(get_session_info(), get_entries())
        assert "<html" in html
        assert "Diana" in html
        assert "PKI Lab" in html
        assert "DEPRECATED" in html
        assert "FAIL" in html or "badge-fail" in html

    def test_generate_html_report_empty_session(self):
        from core.lab_report import generate_html_report
        info = {
            "student_name": "Test Student",
            "session_title": "Empty Lab",
            "start_time": "2026-01-01T00:00:00+00:00",
            "total_ops": 0,
            "successes": 0,
            "failures": 0,
            "deprecated_used": 0,
        }
        html = generate_html_report(info, [])
        assert "<html" in html
        assert "Test Student" in html
        assert "No operations recorded" in html

    def test_generate_html_report_file(self, tmp_path):
        from core.session_log import start_session, log_entry, get_session_info, get_entries
        from core.lab_report import generate_html_report_file
        start_session("Eve", "File Test Lab")
        log_entry("keymgmt", "gen key", "openssl genpkey", True)
        out = str(tmp_path / "report.html")
        generate_html_report_file(out, get_session_info(), get_entries())
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "Eve" in content
        assert "File Test Lab" in content

    def test_html_escaping(self):
        """Ensure XSS-unsafe characters are escaped in student name."""
        from core.lab_report import generate_html_report
        info = {
            "student_name": "<script>alert('xss')</script>",
            "session_title": "Test",
            "start_time": "",
            "total_ops": 0,
            "successes": 0,
            "failures": 0,
            "deprecated_used": 0,
        }
        html = generate_html_report(info, [])
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_report_contains_stats_grid(self):
        from core.lab_report import generate_html_report
        info = {
            "student_name": "Frank",
            "session_title": "Lab",
            "start_time": "2026-01-01T10:00:00+00:00",
            "total_ops": 5,
            "successes": 4,
            "failures": 1,
            "deprecated_used": 2,
        }
        html = generate_html_report(info, [])
        assert "stats-grid" in html
        assert ">5<" in html  # total ops shown
        assert ">4<" in html  # successes shown
        assert ">1<" in html  # failures shown
        assert ">2<" in html  # deprecated shown

    def test_html_report_success_rate(self):
        from core.lab_report import generate_html_report
        info = {
            "student_name": "Grace",
            "session_title": "Lab",
            "start_time": "",
            "total_ops": 10,
            "successes": 8,
            "failures": 2,
            "deprecated_used": 0,
        }
        html = generate_html_report(info, [])
        assert "80%" in html

    def test_html_report_instructor_checklist(self):
        from core.lab_report import generate_html_report
        html = generate_html_report(
            {"student_name": "", "session_title": "", "start_time": "",
             "total_ops": 0, "successes": 0, "failures": 0, "deprecated_used": 0},
            []
        )
        assert "Instructor Review Checklist" in html
        assert "checklist" in html

    def test_html_report_command_history(self):
        from core.lab_report import generate_html_report
        from core.session_log import start_session, log_entry, get_session_info, get_entries
        start_session("Henry")
        log_entry("hashing", "SHA-256", "openssl dgst -sha256 secret.txt", True)
        html = generate_html_report(get_session_info(), get_entries())
        assert "Command History" in html
        assert "openssl dgst -sha256 secret.txt" in html

    def test_deprecated_warnings_section(self):
        from core.lab_report import generate_html_report
        from core.session_log import start_session, log_entry, get_session_info, get_entries
        start_session("Iris")
        log_entry("symmetric", "DES", "openssl enc -des", True, deprecated=True, deprecated_alg="DES")
        html = generate_html_report(get_session_info(), get_entries())
        assert "Deprecated Algorithm" in html or "deprecated" in html.lower()


# ---------------------------------------------------------------------------
# TestAuditLogMirroring
# ---------------------------------------------------------------------------

class TestAuditLogMirroring:
    """Test that audit_log.log_operation mirrors to session_log when active."""

    def test_audit_mirrors_to_session(self, tmp_path, monkeypatch):
        """Operations logged via audit_log should appear in session_log during classroom mode."""
        from core import session_log
        import core.audit_log as al

        # Redirect audit log to tmp file
        def mock_log_path():
            tmp_path.mkdir(exist_ok=True)
            return tmp_path / "audit.log"
        monkeypatch.setattr(al, "_log_path", mock_log_path)

        session_log.start_session("Jake", "Audit Mirror Test")
        al.log_operation("hashing", "sha256", "openssl dgst -sha256 f", True)
        entries = session_log.get_entries()
        assert len(entries) == 1
        assert entries[0]["module"] == "hashing"

    def test_audit_does_not_mirror_when_inactive(self, tmp_path, monkeypatch):
        from core import session_log
        import core.audit_log as al

        def mock_log_path():
            tmp_path.mkdir(exist_ok=True)
            return tmp_path / "audit.log"
        monkeypatch.setattr(al, "_log_path", mock_log_path)

        assert not session_log.is_active()
        al.log_operation("hashing", "sha256", "cmd", True)
        # session_log has no entries since no session is active
        assert session_log.get_entries() == []
