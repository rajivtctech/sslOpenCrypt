"""
core/lab_report.py — HTML lab report generator for Classroom Mode.

Generates a self-contained HTML file from a session_log session.
The report includes:
  - Student name, session title, date/time
  - Summary statistics (total ops, success rate, deprecated usage)
  - Operation table with sequence, module, operation, command, status
  - Command history (copyable)
  - Instructor review checklist section

Usage:
    from core.lab_report import generate_html_report
    from core import session_log
    html = generate_html_report(session_log.get_session_info(), session_log.get_entries())
    with open("lab_report.html", "w") as f:
        f.write(html)
"""

from datetime import datetime, timezone
from html import escape


_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0;
       padding: 24px; font-size: 14px; }
h1 { color: #60a5fa; font-size: 24px; margin-bottom: 4px; }
h2 { color: #93c5fd; font-size: 16px; margin: 20px 0 8px; border-bottom: 1px solid #334155;
     padding-bottom: 6px; }
h3 { color: #7dd3fc; font-size: 13px; margin: 12px 0 6px; }
.header { background: #1e293b; border-radius: 8px; padding: 20px 24px; margin-bottom: 20px;
          border-left: 4px solid #3b82f6; }
.meta { color: #94a3b8; font-size: 12px; margin-top: 8px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
              gap: 12px; margin-bottom: 20px; }
.stat-card { background: #1e293b; border-radius: 6px; padding: 14px 16px; text-align: center; }
.stat-value { font-size: 28px; font-weight: bold; color: #60a5fa; }
.stat-label { font-size: 11px; color: #94a3b8; margin-top: 4px; }
.stat-card.success .stat-value { color: #34d399; }
.stat-card.failure .stat-value { color: #f87171; }
.stat-card.warning .stat-value { color: #fbbf24; }
table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px;
        overflow: hidden; margin-bottom: 20px; font-size: 12px; }
th { background: #334155; color: #93c5fd; padding: 10px 12px; text-align: left;
     font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 9px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
tr:nth-child(even) td { background: #1a2535; }
tr:hover td { background: #243044; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px;
         font-weight: bold; }
.badge-ok  { background: #064e3b; color: #34d399; }
.badge-fail { background: #450a0a; color: #f87171; }
.badge-depr { background: #451a03; color: #fcd34d; }
.cmd { font-family: 'Consolas', 'Courier New', monospace; font-size: 11px;
       background: #0f172a; border: 1px solid #334155; border-radius: 4px;
       padding: 2px 6px; white-space: pre-wrap; word-break: break-all; color: #a5f3fc; }
.cmd-block { font-family: 'Consolas', 'Courier New', monospace; font-size: 11px;
             background: #0f172a; border: 1px solid #334155; border-radius: 6px;
             padding: 12px 14px; white-space: pre; overflow-x: auto; color: #a5f3fc;
             margin-bottom: 8px; line-height: 1.5; }
.ts { color: #64748b; font-size: 10px; }
.checklist { background: #1e293b; border-radius: 8px; padding: 16px 20px; }
.checklist li { margin: 8px 0; list-style: none; padding-left: 0; }
.checklist li::before { content: "☐ "; color: #60a5fa; font-size: 16px; }
.footer { color: #475569; font-size: 11px; text-align: center; margin-top: 28px;
          border-top: 1px solid #1e293b; padding-top: 12px; }
"""


def _badge(success: bool, deprecated: bool) -> str:
    if deprecated:
        return '<span class="badge badge-depr">DEPRECATED</span>'
    if success:
        return '<span class="badge badge-ok">PASS</span>'
    return '<span class="badge badge-fail">FAIL</span>'


def _module_display(module: str) -> str:
    names = {
        "keymgmt": "Key Management", "symmetric": "Symmetric Enc.",
        "hashing": "Hashing", "pki": "PKI & Certs", "signing": "File Signing",
        "smime": "S/MIME", "random": "Random", "tls": "TLS Advisor",
        "edu": "Edu Hub", "gpg": "GnuPG", "vault": "Key Vault",
    }
    return names.get(module, module.title())


def generate_html_report(info: dict, entries: list[dict]) -> str:
    """
    Generate a self-contained HTML lab report.

    info: dict from session_log.get_session_info()
    entries: list from session_log.get_entries()
    Returns: HTML string
    """
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    student = escape(info.get("student_name", "Anonymous"))
    title   = escape(info.get("session_title", "Cryptography Lab Session"))
    start   = info.get("start_time", "")[:19].replace("T", " ") + " UTC" if info.get("start_time") else "—"
    total   = info.get("total_ops", 0)
    successes  = info.get("successes", 0)
    failures   = info.get("failures", 0)
    deprecated = info.get("deprecated_used", 0)
    rate    = f"{100 * successes // total}%" if total else "—"

    # ---- Header ----
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — sslOpenCrypt Lab Report</title>
<style>{_CSS}</style>
</head>
<body>

<div class="header">
  <h1>🔐 sslOpenCrypt — Lab Report</h1>
  <div style="font-size:18px; color:#e2e8f0; margin-top:6px;">{title}</div>
  <div class="meta">
    Student: <strong style="color:#e2e8f0">{student}</strong> &nbsp;|&nbsp;
    Session started: {start} &nbsp;|&nbsp;
    Report generated: {generated_at}
  </div>
</div>

<h2>Summary</h2>
<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-value">{total}</div>
    <div class="stat-label">Total Operations</div>
  </div>
  <div class="stat-card success">
    <div class="stat-value">{successes}</div>
    <div class="stat-label">Succeeded</div>
  </div>
  <div class="stat-card failure">
    <div class="stat-value">{failures}</div>
    <div class="stat-label">Failed</div>
  </div>
  <div class="stat-card">
    <div class="stat-value">{rate}</div>
    <div class="stat-label">Success Rate</div>
  </div>
  <div class="stat-card warning">
    <div class="stat-value">{deprecated}</div>
    <div class="stat-label">Deprecated Alg. Used</div>
  </div>
</div>
"""

    # ---- Operation table ----
    html += "<h2>Operations Log</h2>\n"
    if not entries:
        html += "<p style='color:#64748b'>No operations recorded in this session.</p>\n"
    else:
        html += """<table>
<thead><tr>
  <th>#</th><th>Time</th><th>Module</th><th>Operation</th><th>Status</th>
</tr></thead>
<tbody>
"""
        for e in entries:
            ts_short = e.get("ts", "")[:19].replace("T", " ")
            html += (
                f"<tr>"
                f"<td>{e['seq']}</td>"
                f"<td class='ts'>{escape(ts_short)}</td>"
                f"<td>{escape(_module_display(e['module']))}</td>"
                f"<td>{escape(e['operation'])}"
                + (f"<br><span class='cmd'>{escape(e['command'][:120])}</span>" if e.get("command") else "")
                + (f"<br><em style='color:#94a3b8;font-size:10px'>{escape(e['note'])}</em>" if e.get("note") else "")
                + f"</td>"
                f"<td>{_badge(e['success'], e['deprecated'])}</td>"
                f"</tr>\n"
            )
        html += "</tbody></table>\n"

    # ---- Command history ----
    cmds = [e["command"] for e in entries if e.get("command")]
    if cmds:
        html += "<h2>Command History</h2>\n"
        html += "<p style='color:#94a3b8;font-size:12px;margin-bottom:8px'>All OpenSSL/GPG commands executed during this session:</p>\n"
        for e in entries:
            if e.get("command"):
                status_col = "#34d399" if e["success"] else "#f87171"
                html += (
                    f"<div style='margin-bottom:6px'>"
                    f"<span style='color:#64748b;font-size:10px'>#{e['seq']} "
                    f"[{_module_display(e['module'])}] "
                    f"<span style='color:{status_col}'>{'✓' if e['success'] else '✗'}</span></span>"
                    f"<div class='cmd-block'>{escape(e['command'])}</div>"
                    f"</div>\n"
                )

    # ---- Deprecated algorithm warnings ----
    depr_entries = [e for e in entries if e.get("deprecated")]
    if depr_entries:
        html += "<h2>⚠️ Deprecated Algorithm Usage</h2>\n"
        html += "<p style='color:#fcd34d;font-size:12px;margin-bottom:8px'>The following operations used deprecated algorithms. These should not be used in production:</p>\n"
        html += "<ul style='list-style:none;padding:0'>\n"
        for e in depr_entries:
            html += (
                f"<li style='background:#451a03;border-radius:6px;padding:8px 12px;margin:4px 0'>"
                f"<strong style='color:#fcd34d'>#{e['seq']} {escape(e['operation'])}</strong> "
                f"— {escape(e.get('deprecated_alg',''))}</li>\n"
            )
        html += "</ul>\n"

    # ---- Instructor checklist ----
    html += """
<h2>Instructor Review Checklist</h2>
<div class="checklist">
<ul>
  <li>Student correctly generated an asymmetric key pair</li>
  <li>Student successfully encrypted and decrypted a file</li>
  <li>Student verified a digital signature</li>
  <li>Student created and inspected a self-signed certificate</li>
  <li>Student did NOT use deprecated algorithms unnecessarily</li>
  <li>All operations completed with success status</li>
  <li>Student can explain the OpenSSL commands shown in the Command Console</li>
</ul>
</div>
"""

    html += f"""
<div class="footer">
  Generated by <strong>sslOpenCrypt</strong> v1.0 — Open-Source GUI for OpenSSL, PKI &amp; Encryption<br>
  Licensed under GPL v3 · <a href="https://tctech.co.in" style="color:#60a5fa">tctech.co.in</a>
</div>

</body>
</html>"""

    return html


def generate_html_report_file(output_path: str, info: dict, entries: list[dict]) -> None:
    """Write the HTML lab report to a file."""
    html = generate_html_report(info, entries)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
