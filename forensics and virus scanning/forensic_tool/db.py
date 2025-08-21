from __future__ import annotations
import sqlite3
import threading
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from .constants import DEFAULT_DB_NAME
from .logger import get_logger

logger = get_logger()


class ForensicDB:
    """SQLite wrapper to store hash history."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else Path(DEFAULT_DB_NAME)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        if not self._conn:
            # Allow use from worker thread; we protect with a lock.
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        return self._conn

    def _ensure_schema(self):
        con = self._connect()
        cur = con.cursor()
        with self._lock:
            cur.execute(
            """
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                md5 TEXT,
                sha256 TEXT NOT NULL,
                size INTEGER,
                mtime REAL,
                scanned_at TEXT NOT NULL
            );
            """
            )
            cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_file_hashes_path_sha256
            ON file_hashes(path, sha256);
            """
            )
            con.commit()

    def insert_file_hash(self, path: str, md5: str, sha256: str, size: int, mtime: float, scanned_at: str):
        con = self._connect()
        cur = con.cursor()
        with self._lock:
            cur.execute(
            """
            INSERT INTO file_hashes (path, md5, sha256, size, mtime, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (path, md5, sha256, size, mtime, scanned_at),
            )
            con.commit()

    def get_last_hash(self, path: str) -> Optional[Tuple[str, str]]:
        """Return last (md5, sha256) for path if exists."""
        con = self._connect()
        cur = con.cursor()
        with self._lock:
            cur.execute(
            """
            SELECT md5, sha256 FROM file_hashes
            WHERE path = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (path,),
            )
            row = cur.fetchone()
        return (row[0], row[1]) if row else None

    # Deprecated VT cache removed

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None
