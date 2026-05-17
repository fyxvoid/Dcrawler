"""
Module 4 – Storage & Security
Manages encrypted SQLite persistence for investigation sessions, results, and audit logs.
"""
import csv
import io
import os
import json
import sqlite3
import hashlib
import secrets
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

DB_PATH = Path(os.getenv("DCRAWLER_DB", "dcrawler.db"))
KEY_FILE = Path(os.getenv("DCRAWLER_KEY", ".dcrawler.key"))


# ── Key management ──────────────────────────────────────────────────────────

def _load_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


def _cipher() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt(plaintext: str) -> str:
    return _cipher().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return _cipher().decrypt(ciphertext.encode()).decode()


# ── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT UNIQUE NOT NULL,
    query        TEXT NOT NULL,
    refined_q    TEXT,
    model        TEXT,
    preset       TEXT DEFAULT 'threat_intel',
    result_count INTEGER DEFAULT 0,
    scrape_count INTEGER DEFAULT 0,
    summary      TEXT,          -- encrypted
    created_at   TEXT NOT NULL,
    finished_at  TEXT,
    tags         TEXT DEFAULT '',
    notes        TEXT DEFAULT '',
    threat_score INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    url         TEXT NOT NULL,
    title       TEXT,
    content     TEXT,          -- encrypted
    scraped     INTEGER DEFAULT 0,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT NOT NULL,
    session_id  TEXT,
    details     TEXT,
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    kind        TEXT NOT NULL,  -- email, domain, ip, crypto_addr, threat_actor, etc.
    value       TEXT NOT NULL,
    context     TEXT,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
"""


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        # Migrate existing databases to add new columns if missing
        existing = {row[1] for row in conn.execute("PRAGMA table_info(sessions)").fetchall()}
        for col, definition in [
            ("tags", "TEXT DEFAULT ''"),
            ("notes", "TEXT DEFAULT ''"),
            ("threat_score", "INTEGER DEFAULT 0"),
        ]:
            if col not in existing:
                conn.execute(f"ALTER TABLE sessions ADD COLUMN {col} {definition}")
    logger.info("Database initialised at %s", DB_PATH)


# ── Session CRUD ────────────────────────────────────────────────────────────

def new_session(query: str, model: str, preset: str = "threat_intel") -> str:
    sid = secrets.token_hex(12)
    ts = _now()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (session_id, query, model, preset, created_at) VALUES (?,?,?,?,?)",
            (sid, query, model, preset, ts),
        )
    log_event("SESSION_START", sid, {"query": query, "model": model, "preset": preset})
    return sid


def update_session(
    sid: str,
    *,
    refined_q: Optional[str] = None,
    result_count: Optional[int] = None,
    scrape_count: Optional[int] = None,
    summary: Optional[str] = None,
    finished: bool = False,
    tags: Optional[str] = None,
    notes: Optional[str] = None,
    threat_score: Optional[int] = None,
):
    fields, vals = [], []
    if refined_q is not None:
        fields.append("refined_q = ?"); vals.append(refined_q)
    if result_count is not None:
        fields.append("result_count = ?"); vals.append(result_count)
    if scrape_count is not None:
        fields.append("scrape_count = ?"); vals.append(scrape_count)
    if summary is not None:
        fields.append("summary = ?"); vals.append(encrypt(summary))
    if finished:
        fields.append("finished_at = ?"); vals.append(_now())
    if tags is not None:
        fields.append("tags = ?"); vals.append(tags)
    if notes is not None:
        fields.append("notes = ?"); vals.append(notes)
    if threat_score is not None:
        fields.append("threat_score = ?"); vals.append(threat_score)
    if not fields:
        return
    vals.append(sid)
    with get_conn() as conn:
        conn.execute(f"UPDATE sessions SET {', '.join(fields)} WHERE session_id = ?", vals)


def get_session(sid: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("summary"):
        try:
            d["summary"] = decrypt(d["summary"])
        except Exception:
            pass
    return d


def list_sessions(limit: int = 50, tag: Optional[str] = None) -> list[dict]:
    if tag:
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT id, session_id, query, model, preset, result_count, scrape_count, "
                "created_at, finished_at, tags, notes, threat_score "
                "FROM sessions WHERE tags LIKE ? ORDER BY id DESC LIMIT ?",
                (f"%{tag}%", limit),
            ).fetchall()
    else:
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT id, session_id, query, model, preset, result_count, scrape_count, "
                "created_at, finished_at, tags, notes, threat_score "
                "FROM sessions ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def delete_session(sid: str):
    with get_conn() as conn:
        conn.execute("DELETE FROM results WHERE session_id = ?", (sid,))
        conn.execute("DELETE FROM artifacts WHERE session_id = ?", (sid,))
        conn.execute("DELETE FROM sessions WHERE session_id = ?", (sid,))
    log_event("SESSION_DELETE", sid, {})


# ── Results CRUD ────────────────────────────────────────────────────────────

def save_results(sid: str, results: list[dict]):
    ts = _now()
    with get_conn() as conn:
        for r in results:
            conn.execute(
                "INSERT OR IGNORE INTO results (session_id, url, title, scraped, created_at) VALUES (?,?,?,0,?)",
                (sid, r.get("link", ""), r.get("title", ""), ts),
            )


def save_scraped_content(sid: str, scraped: dict[str, str]):
    ts = _now()
    with get_conn() as conn:
        for url, content in scraped.items():
            enc = encrypt(content[:10000])
            conn.execute(
                "UPDATE results SET content = ?, scraped = 1 WHERE session_id = ? AND url = ?",
                (enc, sid, url),
            )
            if not conn.execute(
                "SELECT id FROM results WHERE session_id = ? AND url = ?", (sid, url)
            ).fetchone():
                conn.execute(
                    "INSERT INTO results (session_id, url, content, scraped, created_at) VALUES (?,?,?,1,?)",
                    (sid, url, enc, ts),
                )


def get_results(sid: str, scraped_only: bool = False) -> list[dict]:
    query = "SELECT url, title, scraped FROM results WHERE session_id = ?"
    if scraped_only:
        query += " AND scraped = 1"
    with get_conn() as conn:
        rows = conn.execute(query, (sid,)).fetchall()
    return [dict(r) for r in rows]


def get_results_with_content(sid: str) -> list[dict]:
    """Return all results including decrypted scraped content."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT url, title, content, scraped, created_at FROM results WHERE session_id = ? ORDER BY scraped DESC, id ASC",
            (sid,),
        ).fetchall()
    out = []
    for row in rows:
        d = dict(row)
        if d.get("content"):
            try:
                d["content"] = decrypt(d["content"])
            except Exception:
                d["content"] = ""
        out.append(d)
    return out


# ── Artifact storage ─────────────────────────────────────────────────────────

def save_artifacts(sid: str, artifacts: list[dict]):
    ts = _now()
    with get_conn() as conn:
        for a in artifacts:
            conn.execute(
                "INSERT INTO artifacts (session_id, kind, value, context, created_at) VALUES (?,?,?,?,?)",
                (sid, a.get("kind", "unknown"), a.get("value", ""), a.get("context", ""), ts),
            )


def get_artifacts(sid: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT kind, value, context, created_at FROM artifacts WHERE session_id = ? ORDER BY kind",
            (sid,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Audit log ────────────────────────────────────────────────────────────────

def log_event(event_type: str, session_id: Optional[str], details: dict):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO audit_logs (event_type, session_id, details, created_at) VALUES (?,?,?,?)",
            (event_type, session_id, json.dumps(details), _now()),
        )


def get_audit_log(limit: int = 100, session_id: Optional[str] = None) -> list[dict]:
    if session_id:
        q = "SELECT * FROM audit_logs WHERE session_id = ? ORDER BY id DESC LIMIT ?"
        params = (session_id, limit)
    else:
        q = "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?"
        params = (limit,)
    with get_conn() as conn:
        rows = conn.execute(q, params).fetchall()
    return [dict(r) for r in rows]


# ── Stats ────────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    with get_conn() as conn:
        total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_results  = conn.execute("SELECT COUNT(*) FROM results").fetchone()[0]
        total_scraped  = conn.execute("SELECT COUNT(*) FROM results WHERE scraped=1").fetchone()[0]
        total_artifacts= conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        recent = conn.execute(
            "SELECT query, created_at FROM sessions ORDER BY id DESC LIMIT 5"
        ).fetchall()
    return {
        "total_sessions":  total_sessions,
        "total_results":   total_results,
        "total_scraped":   total_scraped,
        "total_artifacts": total_artifacts,
        "recent_queries":  [dict(r) for r in recent],
    }


# ── Export ───────────────────────────────────────────────────────────────────

def export_session_json(sid: str) -> str:
    session = get_session(sid)
    if not session:
        return json.dumps({"error": f"Session {sid} not found"})
    results   = get_results_with_content(sid)
    artifacts = get_artifacts(sid)
    audit     = get_audit_log(session_id=sid)
    payload = {
        "session": session,
        "results": results,
        "artifacts": artifacts,
        "audit_log": audit,
    }
    return json.dumps(payload, indent=2, default=str)


def export_session_csv(sid: str) -> str:
    """Return CSV string of artifacts + results for a session."""
    session   = get_session(sid)
    results   = get_results_with_content(sid)
    artifacts = get_artifacts(sid)

    buf = io.StringIO()
    w = csv.writer(buf)

    if session:
        w.writerow(["# Session", sid, session.get("query", ""), session.get("created_at", "")])
        w.writerow([])

    w.writerow(["## Results"])
    w.writerow(["url", "title", "scraped"])
    for r in results:
        w.writerow([r.get("url", ""), r.get("title", ""), r.get("scraped", 0)])

    w.writerow([])
    w.writerow(["## IOC Artifacts"])
    w.writerow(["kind", "value", "context"])
    for a in artifacts:
        w.writerow([a.get("kind", ""), a.get("value", ""), a.get("context", "")])

    return buf.getvalue()


def export_all_sessions_csv(limit: int = 200) -> str:
    sessions = list_sessions(limit=limit)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["session_id", "query", "model", "preset", "result_count",
                "scrape_count", "threat_score", "tags", "notes", "created_at", "finished_at"])
    for s in sessions:
        w.writerow([
            s.get("session_id", ""), s.get("query", ""), s.get("model", ""),
            s.get("preset", ""), s.get("result_count", 0), s.get("scrape_count", 0),
            s.get("threat_score", 0), s.get("tags", ""), s.get("notes", ""),
            s.get("created_at", ""), s.get("finished_at", ""),
        ])
    return buf.getvalue()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Initialise on import
init_db()
