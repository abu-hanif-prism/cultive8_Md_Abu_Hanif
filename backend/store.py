"""SQLite persistence. One short-lived connection per call (thread-safe, simple).

Each chunk's result is committed as soon as it completes, so finished work
survives a crash or restart.
"""
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, filename TEXT, status TEXT, size_bytes INTEGER,
    bytes_done INTEGER DEFAULT 0, chunks_done INTEGER DEFAULT 0, chunks_failed INTEGER DEFAULT 0,
    log_format TEXT, error TEXT, report_json TEXT, created_at REAL, finished_at REAL,
    started_at REAL, model_seconds REAL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chunk_results (
    job_id TEXT, idx INTEGER, start_line INTEGER, end_line INTEGER, status TEXT,
    attempts INTEGER, error TEXT, findings_json TEXT,
    PRIMARY KEY (job_id, idx)
);
"""


def data_dir() -> Path:
    p = Path(os.getenv("DATA_DIR", Path(__file__).parent / "data"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(data_dir() / "analyzer.db", timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    for col, ddl in (('started_at', 'REAL'), ('model_seconds', 'REAL DEFAULT 0')):  # DBs from older versions
        try:
            conn.execute(f'ALTER TABLE jobs ADD COLUMN {col} {ddl}')
        except sqlite3.OperationalError:
            pass  # column already there
    return conn


def create_job(job_id: str, filename: str, size: int) -> None:
    with closing(_connect()) as c, c:
        c.execute(
            "INSERT INTO jobs (id, filename, status, size_bytes, created_at) VALUES (?,?,?,?,?)",
            (job_id, filename, "queued", size, time.time()),
        )


_JOB_FIELDS = {
    "status", "bytes_done", "chunks_done", "chunks_failed", "log_format", "error", "report_json", "finished_at",
    "started_at", "model_seconds",
}


def update_job(job_id: str, **fields) -> None:
    assert fields.keys() <= _JOB_FIELDS, fields.keys()
    sets = ", ".join(f"{k}=?" for k in fields)
    with closing(_connect()) as c, c:
        c.execute(f"UPDATE jobs SET {sets} WHERE id=?", (*fields.values(), job_id))


def get_job(job_id: str) -> dict | None:
    with closing(_connect()) as c:
        row = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    return dict(row) if row else None


def save_chunk(job_id, idx, start_line, end_line, status, attempts, error, findings) -> None:
    with closing(_connect()) as c, c:
        c.execute(
            "INSERT OR REPLACE INTO chunk_results VALUES (?,?,?,?,?,?,?,?)",
            (job_id, idx, start_line, end_line, status, attempts, error, json.dumps(findings)),
        )


def load_chunks(job_id: str) -> list[dict]:
    with closing(_connect()) as c:
        rows = c.execute("SELECT * FROM chunk_results WHERE job_id=? ORDER BY idx", (job_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
        out.append(d)
    return out
