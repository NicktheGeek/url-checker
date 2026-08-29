"""
Local persistence for past checks -- one SQLite file, no server required.

Every finished report (single check or one item of a batch) gets saved here
so the web UI can browse history and re-export old reports without re-running
the checks.
"""
import json
import sqlite3
import time

from app_paths import DATA_DIR

DB_PATH = DATA_DIR / "history.db"


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            verdict TEXT NOT NULL,
            verdict_summary TEXT NOT NULL,
            report_json TEXT NOT NULL,
            checked_at REAL NOT NULL
        )
        """
    )
    return conn


def save_report(report: dict) -> int:
    """Persist a report (the same dict aggregator.check_url returns) and
    return its new history id."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO history (url, verdict, verdict_summary, report_json, checked_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                report["url"],
                report["verdict"],
                report["verdict_summary"],
                json.dumps(report),
                time.time(),
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_history(limit: int = 100) -> list:
    """Return recent checks, newest first, without the full per-source detail."""
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT id, url, verdict, verdict_summary, checked_at "
            "FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [
        {
            "id": row[0],
            "url": row[1],
            "verdict": row[2],
            "verdict_summary": row[3],
            "checked_at": row[4],
        }
        for row in rows
    ]


def get_report(report_id: int):
    """Return the full saved report dict, or None if it doesn't exist."""
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT report_json FROM history WHERE id = ?", (report_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    report = json.loads(row[0])
    report["id"] = report_id
    return report


def delete_report(report_id: int) -> bool:
    """Delete one history entry. Returns True if a row was actually removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM history WHERE id = ?", (report_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def clear_history() -> int:
    """Delete everything. Returns the number of rows removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM history")
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
