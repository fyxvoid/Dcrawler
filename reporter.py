"""
Module 5 – Reporting & Monitoring
Generates HTML and text intelligence reports and a system health summary.
"""
import os
import re
import json
import time
import socket
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(os.getenv("DCRAWLER_REPORTS", "reports"))
REPORTS_DIR.mkdir(exist_ok=True)


# ── Text report ──────────────────────────────────────────────────────────────

def generate_text_report(session: dict, summary: str, artifacts: list, results: list) -> str:
    sep = "=" * 70
    lines = [
        sep,
        "           DCRAWLER – INTELLIGENCE INVESTIGATION REPORT",
        sep,
        f"  Session ID  : {session.get('session_id', 'N/A')}",
        f"  Query       : {session.get('query', '')}",
        f"  Refined Q   : {session.get('refined_q', '')}",
        f"  Model       : {session.get('model', '')}",
        f"  Preset      : {session.get('preset', 'threat_intel')}",
        f"  Started     : {session.get('created_at', '')}",
        f"  Finished    : {session.get('finished_at', '')}",
        f"  Sources     : {session.get('result_count', 0)} found / "
                         f"{session.get('scrape_count', 0)} scraped",
        sep,
        "",
        "INTELLIGENCE FINDINGS",
        "-" * 70,
        summary or "(no summary generated)",
        "",
    ]

    if artifacts:
        lines += ["", "INVESTIGATION ARTIFACTS", "-" * 70]
        by_kind: dict[str, list] = {}
        for a in artifacts:
            by_kind.setdefault(a["kind"], []).append(a)
        for kind, items in sorted(by_kind.items()):
            lines.append(f"\n  {kind.upper()}:")
            for item in items:
                ctx = f"  [{item.get('context', '')}]" if item.get("context") else ""
                lines.append(f"    • {item['value']}{ctx}")

    if results:
        lines += ["", "", "SOURCE URLS", "-" * 70]
        for r in results:
            lines.append(f"  {r.get('url', '')}")

    lines += ["", sep, f"  Report generated: {_now()}", sep, ""]
    return "\n".join(lines)


def save_text_report(session_id: str, content: str) -> Path:
    path = REPORTS_DIR / f"report_{session_id}.txt"
    path.write_text(content, encoding="utf-8")
    logger.info("Text report saved: %s", path)
    return path


# ── HTML report ──────────────────────────────────────────────────────────────

def generate_html_report(session: dict, summary: str, artifacts: list, results: list) -> str:
    def esc(s: str) -> str:
        return (str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    # Format summary with basic markdown-like rendering
    summary_html = esc(summary or "No summary generated.")
    summary_html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", summary_html)
    summary_html = summary_html.replace("\n\n", "</p><p>").replace("\n", "<br>")
    summary_html = f"<p>{summary_html}</p>"

    artifacts_html = ""
    if artifacts:
        by_kind: dict[str, list] = {}
        for a in artifacts:
            by_kind.setdefault(a["kind"], []).append(a)
        rows = ""
        for kind, items in sorted(by_kind.items()):
            for item in items:
                rows += f"""
                <tr>
                  <td><span class="badge">{esc(kind)}</span></td>
                  <td><code>{esc(item['value'])}</code></td>
                  <td>{esc(item.get('context',''))}</td>
                </tr>"""
        artifacts_html = f"""
        <h2>&#128270; Investigation Artifacts</h2>
        <table>
          <thead><tr><th>Type</th><th>Value</th><th>Context</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    sources_html = ""
    if results:
        items_html = "".join(
            f'<li><a href="{esc(r["url"])}" target="_blank">{esc(r.get("title") or r["url"])}</a></li>'
            for r in results
        )
        sources_html = f"<h2>&#128279; Source URLs</h2><ul>{items_html}</ul>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Dcrawler Report – {esc(session.get('query',''))}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 2rem; }}
    h1 {{ font-size: 1.6rem; color: #58a6ff; margin-bottom: 0.3rem; }}
    h2 {{ font-size: 1.1rem; color: #79c0ff; margin: 1.8rem 0 0.6rem; border-bottom: 1px solid #30363d; padding-bottom: 0.3rem; }}
    .meta {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem 1.4rem; margin: 1rem 0 1.5rem; display: grid; grid-template-columns: 140px 1fr; gap: 0.3rem 0.8rem; font-size: 0.875rem; }}
    .meta dt {{ color: #8b949e; font-weight: 600; }}
    .meta dd {{ color: #c9d1d9; font-family: monospace; word-break: break-all; }}
    .summary {{ background: #161b22; border-left: 3px solid #388bfd; border-radius: 0 6px 6px 0; padding: 1rem 1.4rem; font-size: 0.9rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 0.5rem; }}
    th {{ background: #21262d; padding: 0.5rem 0.8rem; text-align: left; color: #8b949e; border-bottom: 1px solid #30363d; }}
    td {{ padding: 0.45rem 0.8rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
    tr:hover td {{ background: #161b22; }}
    .badge {{ background: #21262d; border: 1px solid #30363d; border-radius: 12px; padding: 0.1rem 0.5rem; font-size: 0.75rem; color: #58a6ff; }}
    code {{ background: #21262d; border-radius: 3px; padding: 0.1rem 0.3rem; font-size: 0.82em; word-break: break-all; }}
    ul {{ list-style: none; padding: 0; }}
    li {{ padding: 0.3rem 0; border-bottom: 1px solid #21262d; font-size: 0.85rem; }}
    li a {{ color: #58a6ff; text-decoration: none; word-break: break-all; }}
    li a:hover {{ text-decoration: underline; }}
    .footer {{ margin-top: 3rem; color: #484f58; font-size: 0.78rem; text-align: center; }}
    .tag {{ display: inline-block; background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb66; border-radius: 3px; padding: 0.1rem 0.4rem; font-size: 0.75rem; margin-right: 0.3rem; }}
  </style>
</head>
<body>
  <h1>&#128373; Dcrawler Intelligence Report</h1>
  <dl class="meta">
    <dt>Session ID</dt>  <dd>{esc(session.get('session_id',''))}</dd>
    <dt>Query</dt>       <dd>{esc(session.get('query',''))}</dd>
    <dt>Refined Query</dt><dd>{esc(session.get('refined_q',''))}</dd>
    <dt>Model</dt>       <dd>{esc(session.get('model',''))}</dd>
    <dt>Preset</dt>      <dd><span class="tag">{esc(session.get('preset','threat_intel'))}</span></dd>
    <dt>Started</dt>     <dd>{esc(session.get('created_at',''))}</dd>
    <dt>Finished</dt>    <dd>{esc(session.get('finished_at',''))}</dd>
    <dt>Sources</dt>     <dd>{session.get('result_count',0)} found &nbsp;/&nbsp; {session.get('scrape_count',0)} scraped</dd>
  </dl>

  <h2>&#127755; Intelligence Findings</h2>
  <div class="summary">{summary_html}</div>

  {artifacts_html}

  {sources_html}

  <p class="footer">Generated by Dcrawler – AI-Powered Dark Web OSINT &nbsp;|&nbsp; {_now()}</p>
</body>
</html>"""


def save_html_report(session_id: str, content: str) -> Path:
    path = REPORTS_DIR / f"report_{session_id}.html"
    path.write_text(content, encoding="utf-8")
    logger.info("HTML report saved: %s", path)
    return path


# ── System health report ─────────────────────────────────────────────────────

def get_system_health() -> dict:
    health: dict = {"timestamp": _now(), "components": {}}

    # Tor
    try:
        s = socket.create_connection(("127.0.0.1", 9050), timeout=3)
        s.close()
        health["components"]["tor"] = {"status": "up", "note": "SOCKS5 proxy reachable"}
    except Exception as e:
        health["components"]["tor"] = {"status": "down", "note": str(e)}

    # Database
    try:
        from storage import get_conn, get_stats
        stats = get_stats()
        health["components"]["database"] = {
            "status": "up",
            "sessions": stats["total_sessions"],
            "results":  stats["total_results"],
            "scraped":  stats["total_scraped"],
        }
    except Exception as e:
        health["components"]["database"] = {"status": "error", "note": str(e)}

    # Reports directory
    try:
        count = len(list(REPORTS_DIR.glob("report_*")))
        health["components"]["reports"] = {"status": "up", "count": count, "path": str(REPORTS_DIR)}
    except Exception as e:
        health["components"]["reports"] = {"status": "error", "note": str(e)}

    overall = all(
        c.get("status") == "up" for c in health["components"].values()
    )
    health["overall"] = "healthy" if overall else "degraded"
    return health


def print_health_report():
    h = get_system_health()
    print(f"\n{'─'*50}")
    print(f"  SYSTEM HEALTH  [{h['timestamp']}]")
    print(f"  Overall: {h['overall'].upper()}")
    print(f"{'─'*50}")
    for name, info in h["components"].items():
        status = info.get("status", "?")
        icon = "✓" if status == "up" else "✗"
        extras = {k: v for k, v in info.items() if k not in ("status",)}
        detail = "  ".join(f"{k}={v}" for k, v in extras.items())
        print(f"  {icon} {name.upper():12s} {status.upper():8s}  {detail}")
    print(f"{'─'*50}\n")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
