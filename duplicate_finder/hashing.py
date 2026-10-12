"""Exact-content hashing and byte comparison.

All readers stream the file in fixed-size chunks, so memory use is bounded by
``chunk_size`` regardless of file size.  Each reader compares the file's stat
fingerprint before and after reading and raises :class:`SourceChanged` if the
file was modified while it was being read.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional, Tuple

from .errors import SourceChanged
from .models import StatFingerprint
from .runtime import CancelToken

PARTIAL_BLOCK = 64 * 1024


def _same_content_state(a: StatFingerprint, b: StatFingerprint) -> bool:
    return a.size == b.size and a.mtime_ns == b.mtime_ns and a.ino == b.ino and a.dev == b.dev


def _open_checked(path: Path, expected: Optional[StatFingerprint]):
    fh = open(path, "rb")
    try:
        before = StatFingerprint.from_stat(os.fstat(fh.fileno()))
        if expected is not None and not _same_content_state(before, expected):
            raise SourceChanged(f"{path} changed since it was scanned")
    except BaseException:
        fh.close()
        raise
    return fh, before


def _check_after(path: Path, fh, before: StatFingerprint) -> StatFingerprint:
    after = StatFingerprint.from_stat(os.fstat(fh.fileno()))
    if not _same_content_state(before, after):
        raise SourceChanged(f"{path} changed while it was being read")
    try:
        on_disk = StatFingerprint.from_stat(os.stat(path, follow_symlinks=False))
    except OSError as exc:
        raise SourceChanged(f"{path} disappeared while it was being read: {exc}") from exc
    if before.has_identity() and on_disk.identity != before.identity:
        raise SourceChanged(f"{path} was replaced while it was being read")
    return after


def sha256_file(path: Path, chunk_size: int = 1024 * 1024, cancel: Optional[CancelToken] = None,
                expected: Optional[StatFingerprint] = None) -> Tuple[str, StatFingerprint]:
    """Return ``(hex digest, fingerprint)`` of the complete file."""
    h = hashlib.sha256()
    fh, before = _open_checked(path, expected)
    with fh:
        while True:
            if cancel is not None:
                cancel.check()
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
        fp = _check_after(path, fh, before)
    return h.hexdigest(), fp


def partial_hash(path: Path, expected: Optional[StatFingerprint] = None, block: int = PARTIAL_BLOCK) -> str:
    """Cheap pre-filter: hash of size + first block + last block.

    Never used as evidence of equality, only to rule out candidates early.
    """
    h = hashlib.sha256()
    fh, before = _open_checked(path, expected)
    with fh:
        h.update(str(before.size).encode())
        h.update(fh.read(block))
        if before.size > 2 * block:
            fh.seek(before.size - block)
            h.update(fh.read(block))
        _check_after(path, fh, before)
    return h.hexdigest()


def files_identical(a: Path, b: Path, chunk_size: int = 1024 * 1024,
                    cancel: Optional[CancelToken] = None) -> bool:
    """Full byte-for-byte comparison of two files."""
    fa, ba = _open_checked(a, None)
    with fa:
        fb, bb = _open_checked(b, None)
        with fb:
            if ba.size != bb.size:
                return False
            while True:
                if cancel is not None:
                    cancel.check()
                ca = fa.read(chunk_size)
                cb = fb.read(chunk_size)
                if ca != cb:
                    return False
                if not ca:
                    break
            _check_after(a, fa, ba)
            _check_after(b, fb, bb)
    return True
