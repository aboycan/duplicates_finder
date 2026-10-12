"""Append-only, fsync'd JSON-lines transaction journal.

Every relocation (and every restore) is a transaction made of ordered events::

    intent -> dest_reserved -> dest_verified -> source_removed -> committed
                     \\-> failed (source retained)

Each event is written and flushed to stable storage *before* the filesystem
action it announces, so after a crash the journal always describes a superset
of what may have happened.  The journal is never rewritten or truncated;
recovery appends new events.  It is the authority for ``recover``,
``restore`` and the relocation manifest.

A process-level lock (``fcntl``/``msvcrt``, released automatically if the
process dies) prevents two organising runs from interleaving.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .errors import JournalError

TERMINAL_EVENTS = {"committed", "failed", "aborted", "recovered_committed", "recovered_aborted"}


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds")


def new_tx_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Transaction:
    tx_id: str
    events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def intent(self) -> Dict[str, Any]:
        for e in self.events:
            if e.get("event") == "intent":
                return e
        return {}

    @property
    def kind(self) -> str:
        return self.intent.get("kind", "move")

    @property
    def last_event(self) -> str:
        return self.events[-1]["event"] if self.events else ""

    def has(self, event: str) -> bool:
        return any(e.get("event") == event for e in self.events)

    def value(self, key: str) -> Any:
        """Latest value of *key* across all events."""
        for e in reversed(self.events):
            if key in e:
                return e[key]
        return None

    @property
    def is_terminal(self) -> bool:
        return any(e.get("event") in TERMINAL_EVENTS for e in self.events)

    @property
    def committed(self) -> bool:
        return any(e.get("event") in ("committed", "recovered_committed") for e in self.events)


class _FileLock:
    """Exclusive advisory lock held for the lifetime of an organising run."""

    def __init__(self, path: Path):
        self.path = path
        self._fh = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b")
        try:
            if sys.platform.startswith("win"):
                import msvcrt
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            fh.close()
            raise JournalError(f"another duplicate_finder process is organising files (lock {self.path})") from exc
        self._fh = fh

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if sys.platform.startswith("win"):
                import msvcrt
                self._fh.seek(0)
                try:
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None


class Journal:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._proc_lock = _FileLock(self.path.with_suffix(".lock"))
        self._locked = False

    # ------------------------------------------------------------------ locking
    def __enter__(self) -> "Journal":
        self.lock()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.unlock()

    def lock(self) -> None:
        if not self._locked:
            self._proc_lock.acquire()
            self._locked = True

    def unlock(self) -> None:
        if self._locked:
            self._proc_lock.release()
            self._locked = False

    # ------------------------------------------------------------------ writing
    def append(self, tx_id: str, event: str, **data: Any) -> Dict[str, Any]:
        record = {"ts": now_iso(), "tx": tx_id, "event": event, **data}
        line = json.dumps(record, ensure_ascii=False, default=str, separators=(",", ":"))
        if "\n" in line:
            raise JournalError("journal record contains a newline")
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = (line + "\n").encode("utf-8", "surrogateescape")
            # If a previous process died mid-line, start on a fresh line so the
            # torn fragment cannot swallow this record.
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    if fh.tell() > 0:
                        fh.seek(-1, os.SEEK_END)
                        if fh.read(1) != b"\n":
                            payload = b"\n" + payload
            except FileNotFoundError:
                pass
            # O_APPEND: every write lands at the end; existing lines are never touched.
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
            try:
                view = memoryview(payload)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            except OSError as exc:
                raise JournalError(f"cannot write transaction journal {self.path}: {exc}") from exc
            finally:
                os.close(fd)
        return record

    # ------------------------------------------------------------------ reading
    def iter_records(self) -> Iterator[Dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw.decode("utf-8", "surrogateescape"))
                except ValueError:
                    # A torn final line from a crash mid-write: the action it
                    # announced was never started, so ignoring it is safe.
                    continue
                if isinstance(rec, dict) and "tx" in rec and "event" in rec:
                    yield rec

    def transactions(self) -> Dict[str, Transaction]:
        txs: Dict[str, Transaction] = {}
        for rec in self.iter_records():
            txs.setdefault(rec["tx"], Transaction(rec["tx"])).events.append(rec)
        return txs

    def incomplete(self) -> List[Transaction]:
        return [t for t in self.transactions().values() if not t.is_terminal]
