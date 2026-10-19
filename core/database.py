"""SQLite persistence."""
import sqlite3
import json
import datetime
from contextlib import contextmanager
from core.config import DB_PATH


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                data TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event TEXT NOT NULL,
                detail TEXT
            )
        """)
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def save_scan(module: str, target: str, data: dict, risk_score: int = 0):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO scans (timestamp, module, target, data, risk_score) "
                "VALUES (?, ?, ?, ?, ?)",
                (datetime.datetime.now().isoformat(), module, target,
                 json.dumps(data, default=str), risk_score),
            )
            conn.commit()
    except Exception:
        pass


def get_scans(limit: int = 100, module: str = None):
    with get_db() as conn:
        if module:
            rows = conn.execute(
                "SELECT * FROM scans WHERE module = ? ORDER BY id DESC LIMIT ?",
                (module, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]


def clear_scans():
    with get_db() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()


def log_event(event: str, detail: str = ""):
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, event, detail) VALUES (?, ?, ?)",
                (datetime.datetime.now().isoformat(), event, detail),
            )
            conn.commit()
    except Exception:
        pass


def get_audit_log(limit: int = 100):
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
