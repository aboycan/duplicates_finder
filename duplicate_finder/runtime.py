"""Cancellation and progress reporting."""

from __future__ import annotations

import sys
import threading
import time
from typing import Optional, TextIO

from .errors import CancelledError


class CancelToken:
    """Cooperative cancellation flag shared between threads.

    Long-running loops call :meth:`check` at safe points.  File relocation
    checks it only *between* transactions, never in the middle of one, so a
    cancellation can never leave a half-finished move behind (an interrupted
    process is handled by recovery instead).
    """

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def check(self) -> None:
        if self._event.is_set():
            raise CancelledError("operation cancelled")


class Progress:
    """Throttled single-line progress output on stderr."""

    def __init__(self, enabled: bool = True, stream: Optional[TextIO] = None, interval: float = 0.5):
        self.enabled = enabled
        self.stream = stream or sys.stderr
        self.interval = interval
        self._last = 0.0
        self._lock = threading.Lock()
        self._dirty = False
        self._tty = bool(getattr(self.stream, "isatty", lambda: False)())

    def update(self, message: str, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        # Non-interactive output (logs, pipes) gets a status line every 5 s.
        interval = self.interval if self._tty else max(self.interval, 5.0)
        with self._lock:
            if not force and now - self._last < interval:
                return
            self._last = now
            if self._tty:
                self.stream.write("\r\033[K" + message[:160])
                self._dirty = True
            else:
                self.stream.write(message + "\n")
            self.stream.flush()

    def done(self, message: str = "") -> None:
        if not self.enabled:
            return
        with self._lock:
            if self._tty and self._dirty:
                self.stream.write("\r\033[K")
                self._dirty = False
            if message:
                self.stream.write(message + "\n")
            self.stream.flush()
