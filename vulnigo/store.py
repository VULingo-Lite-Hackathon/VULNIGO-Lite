"""SQLite state & evidence store. Every claim in a report must trace to a row here."""
import json
import sqlite3
import threading
import time
import uuid
from typing import Any

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, kind TEXT, repo_url TEXT, repo_label TEXT, commit_hash TEXT,
  mode TEXT, side TEXT, status TEXT, created_at REAL, updated_at REAL, meta TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, ts REAL, agent TEXT, type TEXT,
  message TEXT, finding_id TEXT, ok INTEGER, data TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, run_id TEXT, category TEXT, file TEXT, line_start INTEGER, line_end INTEGER,
  function TEXT, param TEXT, hypothesis TEXT, status TEXT, test_ref TEXT, evidence TEXT, source TEXT, data TEXT);
CREATE TABLE IF NOT EXISTS patches (
  id TEXT PRIMARY KEY, run_id TEXT, finding_id TEXT, files TEXT, diff TEXT, explanation TEXT,
  author TEXT, approval_status TEXT, applied_hash TEXT, data TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS test_runs (
  id TEXT PRIMARY KEY, run_id TEXT, kind TEXT, command TEXT, env_id TEXT, exit_code INTEGER,
  output TEXT, started REAL, ended REAL, outcome TEXT, sandboxed INTEGER, data TEXT);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, run_id TEXT, patch_id TEXT, decision TEXT, note TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS pointers (
  id TEXT PRIMARY KEY, run_id TEXT, text TEXT, evidence_ref TEXT, decision TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, sender TEXT, side TEXT, text TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS reports (run_id TEXT PRIMARY KEY, body TEXT, ts REAL);
"""

JSON_COLS = {"meta", "data", "evidence", "files", "body"}

_lock = threading.Lock()
_conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript(SCHEMA)
_conn.commit()


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def _enc(row: dict) -> dict:
    return {k: (json.dumps(v) if k in JSON_COLS and v is not None else v) for k, v in row.items()}


def _dec(row: sqlite3.Row | None) -> dict | None:
    if row is None:
        return None
    out = dict(row)
    for k in JSON_COLS & out.keys():
        if out[k]:
            out[k] = json.loads(out[k])
    return out


def insert(table: str, row: dict) -> dict:
    enc = _enc(row)
    cols = ",".join(enc)
    qs = ",".join("?" for _ in enc)
    with _lock:
        cur = _conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({qs})", list(enc.values()))
        _conn.commit()
    if "id" not in row:
        row = {**row, "id": cur.lastrowid}
    return row


def update(table: str, key: str, key_val: Any, **fields: Any) -> None:
    enc = _enc(fields)
    sets = ",".join(f"{k}=?" for k in enc)
    with _lock:
        _conn.execute(f"UPDATE {table} SET {sets} WHERE {key}=?", [*enc.values(), key_val])
        _conn.commit()


def get(table: str, id_: str, key: str = "id") -> dict | None:
    with _lock:
        row = _conn.execute(f"SELECT * FROM {table} WHERE {key}=?", (id_,)).fetchone()
    return _dec(row)


def list_for(table: str, run_id: str, order: str = "rowid") -> list[dict]:
    with _lock:
        rows = _conn.execute(f"SELECT * FROM {table} WHERE run_id=? ORDER BY {order}", (run_id,)).fetchall()
    return [_dec(r) for r in rows]


def upsert_report(run_id: str, body: dict) -> None:
    with _lock:
        _conn.execute("INSERT OR REPLACE INTO reports (run_id, body, ts) VALUES (?,?,?)",
                      (run_id, json.dumps(body), time.time()))
        _conn.commit()


def recent_runs(limit: int = 20) -> list[dict]:
    with _lock:
        rows = _conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [_dec(r) for r in rows]
