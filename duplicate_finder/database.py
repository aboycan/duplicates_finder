"""SQLite persistence: hash cache, scan history and operation records.

Design notes
------------
* WAL journal mode and short transactions: an interrupted scan can never
  leave the database half-written.
* Schema is versioned (``PRAGMA user_version``) and upgraded by ordered
  migrations.
* A cached hash is returned only if the file's device, inode, size, mtime and
  ctime all still match.  Even then the hash is labelled ``cache`` and every
  file is re-hashed from disk immediately before it is moved, so a stale cache
  entry can never cause a wrong relocation.
* A corrupt database is renamed aside (never deleted) and a fresh one is
  created; the hash cache is a pure optimisation.  The append-only journal,
  not this database, is the authority for recovery and restore.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .errors import DatabaseError
from .models import StatFingerprint

SCHEMA_VERSION = 2

_MIGRATIONS: List[Tuple[int, str]] = [
    (1, """
        CREATE TABLE IF NOT EXISTS hash_cache (
            path      TEXT PRIMARY KEY,
            dev       INTEGER NOT NULL,
            ino       INTEGER NOT NULL,
            size      INTEGER NOT NULL,
            mtime_ns  INTEGER NOT NULL,
            ctime_ns  INTEGER NOT NULL,
            partial   TEXT,
            sha256    TEXT,
            hashed_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hash_cache_sha ON hash_cache(sha256);
        CREATE TABLE IF NOT EXISTS scans (
            id        TEXT PRIMARY KEY,
            started   REAL NOT NULL,
            finished  REAL,
            roots     TEXT NOT NULL,
            mode      TEXT NOT NULL,
            action    TEXT NOT NULL,
            status    TEXT NOT NULL,
            summary   TEXT
        );
    """),
    (2, """
        CREATE TABLE IF NOT EXISTS operations (
            tx_id       TEXT PRIMARY KEY,
            scan_id     TEXT,
            kind        TEXT NOT NULL,
            source      TEXT NOT NULL,
            destination TEXT,
            original    TEXT,
            sha256      TEXT,
            size        INTEGER,
            status      TEXT NOT NULL,
            updated     REAL NOT NULL,
            detail      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_operations_scan ON operations(scan_id);
    """),
]


_U64 = 1 << 64
_I64_MAX = (1 << 63) - 1


def _i64(value: int) -> int:
    """Map an unsigned 64-bit value onto SQLite's signed INTEGER range (exact, reversible).

    Windows reports NTFS file IDs and volume serial numbers as unsigned 64-bit
    numbers that can exceed 2**63-1; SQLite INTEGER is signed 64-bit.
    """
    value = int(value)
    if value > _I64_MAX:
        value -= _U64
    if not -(1 << 63) <= value <= _I64_MAX:
        raise OverflowError(f"value {value} does not fit in 64 bits")
    return value


def _row_fp(fp: StatFingerprint) -> tuple:
    return (_i64(fp.dev), _i64(fp.ino), _i64(fp.size), _i64(fp.mtime_ns), _i64(fp.ctime_ns))


def _key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


class Database:
    def __init__(self, path: Path, enabled: bool = True):
        self.path = Path(path)
        self.enabled = enabled
        self.recovered_from_corruption: Optional[Path] = None
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        if enabled:
            self._open()

    # ------------------------------------------------------------------ setup
    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _open(self) -> None:
        try:
            conn = self._connect()
            row = conn.execute("PRAGMA quick_check").fetchone()
            if not row or row[0] != "ok":
                conn.close()
                raise sqlite3.DatabaseError(f"integrity check failed: {row}")
            self._conn = conn
            self._migrate()
        except sqlite3.DatabaseError as exc:
            self._quarantine(exc)

    def _quarantine(self, exc: Exception) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None
        stamp = int(time.time())
        aside = self.path.with_name(f"{self.path.name}.corrupt-{stamp}")
        n = 0
        while any(Path(str(aside) + s).exists() for s in ("", "-wal", "-shm")):
            n += 1
            aside = self.path.with_name(f"{self.path.name}.corrupt-{stamp}-{n}")
        moved = False
        for suffix in ("", "-wal", "-shm"):
            src = Path(str(self.path) + suffix)
            if src.exists():
                try:
                    os.rename(src, Path(str(aside) + suffix))
                    moved = True
                except OSError as err:
                    raise DatabaseError(f"state database {self.path} is corrupt ({exc}) and could not be "
                                        f"moved aside ({err}); move it manually or use --no-cache") from err
        self.recovered_from_corruption = aside if moved else None
        try:
            self._conn = self._connect()
            self._migrate()
        except sqlite3.Error as err:
            raise DatabaseError(f"cannot create state database {self.path}: {err}") from err

    def _migrate(self) -> None:
        assert self._conn is not None
        current = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise DatabaseError(f"state database schema v{current} is newer than this program (v{SCHEMA_VERSION})")
        for version, sql in _MIGRATIONS:
            if version > current:
                with self._lock:
                    self._conn.execute("BEGIN IMMEDIATE")
                    try:
                        for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                            self._conn.execute(stmt)
                        self._conn.execute(f"PRAGMA user_version={version}")
                        self._conn.execute("COMMIT")
                    except sqlite3.Error:
                        self._conn.execute("ROLLBACK")
                        raise

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------ hash cache
    def get_cached(self, path: Path, fp: StatFingerprint) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(partial, sha256)`` if a fully matching cache entry exists."""
        if not self.enabled or self._conn is None:
            return None, None
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT dev, ino, size, mtime_ns, ctime_ns, partial, sha256 FROM hash_cache WHERE path=?",
                    (_key(path),)).fetchone()
            except sqlite3.DatabaseError:
                return None, None
        if not row:
            return None, None
        dev, ino, size, mtime_ns, ctime_ns, partial, sha = row
        if (dev, ino, size, mtime_ns, ctime_ns) != _row_fp(fp):
            return None, None  # stale: file changed (or replaced) since it was hashed
        return partial, sha

    def put_hashes(self, items: Iterable[Tuple[Path, StatFingerprint, Optional[str], Optional[str]]]) -> None:
        if not self.enabled or self._conn is None:
            return
        rows = [(_key(p), *_row_fp(fp), partial, sha, time.time())
                for p, fp, partial, sha in items]
        if not rows:
            return
        with self._lock:
            try:
                self._conn.execute("BEGIN")
                same = ("hash_cache.dev=excluded.dev AND hash_cache.ino=excluded.ino AND "
                        "hash_cache.size=excluded.size AND hash_cache.mtime_ns=excluded.mtime_ns AND "
                        "hash_cache.ctime_ns=excluded.ctime_ns")
                self._conn.executemany(
                    """INSERT INTO hash_cache(path, dev, ino, size, mtime_ns, ctime_ns, partial, sha256, hashed_at)
                       VALUES (?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(path) DO UPDATE SET dev=excluded.dev, ino=excluded.ino, size=excluded.size,
                         mtime_ns=excluded.mtime_ns, ctime_ns=excluded.ctime_ns,
                         partial=COALESCE(excluded.partial, CASE WHEN {same} THEN hash_cache.partial END),
                         sha256=COALESCE(excluded.sha256, CASE WHEN {same} THEN hash_cache.sha256 END),
                         hashed_at=excluded.hashed_at""".replace("{same}", same), rows)
                self._conn.execute("COMMIT")
            except sqlite3.Error:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass

    def invalidate(self, path: Path) -> None:
        if not self.enabled or self._conn is None:
            return
        with self._lock:
            self._conn.execute("DELETE FROM hash_cache WHERE path=?", (_key(path),))

    def clear_cache(self) -> int:
        if not self.enabled or self._conn is None:
            return 0
        with self._lock:
            cur = self._conn.execute("DELETE FROM hash_cache")
            return cur.rowcount

    def cache_stats(self) -> Dict[str, Any]:
        if not self.enabled or self._conn is None:
            return {"enabled": False}
        with self._lock:
            n = self._conn.execute("SELECT COUNT(*), COUNT(sha256) FROM hash_cache").fetchone()
            s = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()
            o = self._conn.execute("SELECT COUNT(*) FROM operations").fetchone()
        return {"enabled": True, "path": str(self.path), "entries": n[0], "full_hashes": n[1],
                "scans": s[0], "operations": o[0]}

    # ------------------------------------------------------------------ scans / operations
    def start_scan(self, scan_id: str, roots: List[Path], mode: str, action: str) -> None:
        if not self.enabled or self._conn is None:
            return
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans(id, started, roots, mode, action, status) VALUES (?,?,?,?,?,?)",
                (scan_id, time.time(), json.dumps([str(r) for r in roots]), mode, action, "running"))

    def finish_scan(self, scan_id: str, status: str, summary: Dict[str, Any]) -> None:
        if not self.enabled or self._conn is None:
            return
        with self._lock:
            self._conn.execute("UPDATE scans SET finished=?, status=?, summary=? WHERE id=?",
                               (time.time(), status, json.dumps(summary, default=str), scan_id))

    def record_operation(self, tx_id: str, scan_id: str, kind: str, source: str, destination: Optional[str],
                         original: Optional[str], sha256: Optional[str], size: Optional[int],
                         status: str, detail: str = "") -> None:
        if not self.enabled or self._conn is None:
            return
        with self._lock:
            try:
                self._conn.execute(
                    """INSERT INTO operations(tx_id, scan_id, kind, source, destination, original, sha256, size,
                                              status, updated, detail)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(tx_id) DO UPDATE SET status=excluded.status, updated=excluded.updated,
                         detail=excluded.detail, destination=COALESCE(excluded.destination, operations.destination)""",
                    (tx_id, scan_id, kind, source, destination, original, sha256, size, status, time.time(), detail))
            except sqlite3.Error:
                pass  # the journal remains authoritative
