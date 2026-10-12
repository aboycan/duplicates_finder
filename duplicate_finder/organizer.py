"""Safe relocation of duplicate copies.

The move procedure (one journaled transaction per file):

 1. source still exists, is a regular file (not a link) and is inside a scan root
 2. source stat fingerprint unchanged since the scan
 3. source and retained original are freshly re-hashed (and byte-compared in
    ``verify="bytes"`` mode); the duplicate relationship must still hold
 4. destination directory resolves inside the ``Duplicates`` directory
 5. ``intent`` journaled (fsync) before anything touches the filesystem
 6. destination name reserved *exclusively*: ``os.link`` (same filesystem) or
    ``O_CREAT|O_EXCL`` (copy) -- both fail instead of overwriting
 7. copy path: stream + fsync, then re-read the destination from disk
 8. destination verified (same inode for a link, SHA-256 for a copy)
 9. final re-check of source, original and destination
10. only then is the source name removed -- in exactly one function,
    :func:`_remove_source_after_verified_move`, the single file-removal call
    in the whole code base (enforced by a test).

If anything fails before step 10 the source is retained and the failure is
reported.  There is no code path that deletes a file because a move failed.
"""

from __future__ import annotations

import errno
import hashlib
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set

from .config import Config
from .database import Database
from .errors import CancelledError, JournalError, SafetyViolation, SourceChanged, VerificationFailed
from .hashing import files_identical, sha256_file
from .models import DuplicateGroup, FileRecord, MatchClass, MoveStatus, PlannedMove, StatFingerprint
from .runtime import CancelToken, Progress
from .safety import absolute, assert_within, is_within, safe_relative, same_file, sanitize_component
from .transaction_log import Journal, new_tx_id, now_iso

MAX_COLLISION_INDEX = 9999
_O_BINARY = getattr(os, "O_BINARY", 0)
_os_write = os.write  # indirection so tests can simulate a full disk for copies only
# errno values meaning "hard links are not possible here, fall back to copying"
_LINK_FALLBACK_ERRNOS = {errno.EXDEV, errno.EPERM, errno.EACCES, errno.EMLINK, errno.ENOTSUP,
                         getattr(errno, "EOPNOTSUPP", errno.ENOTSUP), errno.ENOSYS, errno.EINVAL}


def candidate_names(filename: str, limit: int = MAX_COLLISION_INDEX) -> Iterator[str]:
    """``photo.jpg``, ``photo__duplicate_001.jpg``, ``photo__duplicate_002.jpg`` ..."""
    safe = sanitize_component(filename)
    yield safe
    stem, ext = os.path.splitext(safe)
    for i in range(1, limit + 1):
        yield f"{stem}__duplicate_{i:03d}{ext}"


def _same_content_state(a: StatFingerprint, b: StatFingerprint) -> bool:
    return (a.size, a.mtime_ns, a.dev, a.ino) == (b.size, b.mtime_ns, b.dev, b.ino)


def _fsync_dir(path: Path) -> None:
    if sys.platform.startswith("win"):
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


@dataclass
class TransferResult:
    destination: Path
    method: str  # "link" | "copy"


def reserve_and_transfer(source: Path, dest_dir: Path, names: Iterable[str], expected_sha: str,
                         expected_size: int, journal: Journal, tx_id: str, chunk_size: int,
                         cancel: Optional[CancelToken] = None, allow_link: bool = True,
                         link_func: Callable[[Path, Path], None] = os.link) -> TransferResult:
    """Place verified content of *source* at a new, previously non-existent name.

    Never overwrites: the name is claimed by ``os.link`` or ``O_EXCL`` which
    fail atomically if it exists.  Raises on failure; the source is untouched.
    """
    use_link = allow_link
    for name in names:
        dest = dest_dir / name
        if use_link:
            try:
                link_func(source, dest)
            except FileExistsError:
                continue
            except OSError as exc:
                if exc.errno in _LINK_FALLBACK_ERRNOS or getattr(exc, "winerror", None) in (1, 17, 50, 1142):
                    use_link = False  # cross-device or unsupported: fall back to copy
                else:
                    raise
            else:
                journal.append(tx_id, "dest_reserved", destination=str(dest), method="link")
                _fsync_dir(dest_dir)
                if not same_file(source, dest):
                    raise VerificationFailed(f"hard link {dest} does not refer to {source}")
                return TransferResult(dest, "link")
        # copy path (also reached after a link fallback for this same name)
        try:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o666)
        except FileExistsError:
            continue
        journal.append(tx_id, "dest_reserved", destination=str(dest), method="copy")
        h = hashlib.sha256()
        written = 0
        try:
            with open(source, "rb") as src:
                while True:
                    if cancel is not None and cancel.cancelled:
                        # A cancellation mid-copy leaves the source untouched;
                        # the incomplete copy is reported, never deleted.
                        raise CancelledError("cancelled during copy")
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    h.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        n = _os_write(fd, view)
                        view = view[n:]
                    written += len(chunk)
            os.fsync(fd)
        finally:
            os.close(fd)
        if written != expected_size or h.hexdigest() != expected_sha:
            raise VerificationFailed(f"data read from {source} while copying did not match the verified hash")
        try:
            shutil.copystat(source, dest, follow_symlinks=False)
        except OSError:
            pass  # timestamps/permissions are best-effort; content is what matters
        _fsync_dir(dest_dir)
        # Re-read what actually reached the disk.
        digest, fp = sha256_file(dest, chunk_size, cancel)
        if digest != expected_sha or fp.size != expected_size:
            raise VerificationFailed(f"copy at {dest} does not match the source content")
        return TransferResult(dest, "copy")
    raise SafetyViolation(f"no free destination name in {dest_dir} after {MAX_COLLISION_INDEX} attempts")


def _remove_source_after_verified_move(source: Path, source_fp: StatFingerprint, destination: Path,
                                       expected_size: int, retained: Optional[Path],
                                       retained_fp: Optional[StatFingerprint],
                                       allow_retained_same_inode: bool = False) -> None:
    """Remove the source name as the final step of a verified move.

    This is the ONLY function in the project that removes a file.  It
    re-checks every precondition immediately before acting and raises
    :class:`SafetyViolation` instead of removing anything if one fails.
    """
    # Destination must exist as a regular file with the expected size.
    try:
        dst = os.lstat(destination)
    except OSError as exc:
        raise SafetyViolation(f"destination {destination} vanished before source removal: {exc}") from exc
    if not stat.S_ISREG(dst.st_mode) or dst.st_size != expected_size:
        raise SafetyViolation(f"destination {destination} is not the verified file")

    # Source must be the very file that was verified.
    try:
        sst = os.lstat(source)
    except OSError as exc:
        raise SourceChanged(f"source {source} vanished before removal: {exc}") from exc
    if not stat.S_ISREG(sst.st_mode):
        raise SafetyViolation(f"source {source} is no longer a regular file")
    if not _same_content_state(StatFingerprint.from_stat(sst), source_fp):
        raise SourceChanged(f"source {source} changed after verification")
    if os.path.normcase(os.path.abspath(source)) == os.path.normcase(os.path.abspath(destination)):
        raise SafetyViolation("source and destination are the same path")

    # The retained original must still be there, unchanged, and be a different file.
    if retained is not None:
        try:
            rst = os.lstat(retained)
        except OSError as exc:
            raise SafetyViolation(f"retained original {retained} is missing; refusing to remove {source}") from exc
        if not stat.S_ISREG(rst.st_mode):
            raise SafetyViolation(f"retained original {retained} is not a regular file")
        if retained_fp is not None and not _same_content_state(StatFingerprint.from_stat(rst), retained_fp):
            raise SourceChanged(f"retained original {retained} changed after verification")
        if same_file(source, retained) and not allow_retained_same_inode:
            raise SafetyViolation(f"{source} is the same file as the retained original {retained}")

    os.unlink(source)  # the single sanctioned removal (spec §5, step 10)


class Organizer:
    def __init__(self, cfg: Config, db: Database, journal: Journal, scan_id: str, roots: List[Path],
                 destination: Path, cancel: Optional[CancelToken] = None, progress: Optional[Progress] = None):
        self.cfg = cfg
        self.db = db
        self.journal = journal
        self.scan_id = scan_id
        self.roots = [absolute(r) for r in roots]
        self.destination = absolute(destination)
        self.cancel = cancel or CancelToken()
        self.progress = progress or Progress(False)
        self._link_func: Callable[[Path, Path], None] = os.link  # replaceable in tests

    # ------------------------------------------------------------------ planning
    def destination_dir(self, rec: FileRecord) -> Path:
        base = self.destination
        if self.cfg.layout in ("category", "mirror"):
            base = base / self.cfg.category_dirs.get(rec.category.value, "Other")
        if self.cfg.layout == "mirror":
            root_label = sanitize_component(rec.root.name or rec.root.anchor or "root", "root")
            base = base / root_label / safe_relative(rec.rel_path.parent) if rec.rel_path.parent != Path(".") \
                else base / root_label
        return base

    def plan(self, groups: Iterable[DuplicateGroup]) -> List[PlannedMove]:
        """Propose a destination for every duplicate (no filesystem changes)."""
        taken: Set[str] = set()
        moves: List[PlannedMove] = []
        for g in groups:
            for dup in g.duplicates:
                d_dir = self.destination_dir(dup)
                proposal = None
                for name in candidate_names(dup.path.name):
                    cand = d_dir / name
                    key = os.path.normcase(str(cand)).lower()  # assume case-insensitive: conservative
                    if key in taken or os.path.lexists(cand):
                        continue
                    taken.add(key)
                    proposal = cand
                    break
                moves.append(_planned(g, dup, proposal))
        return moves

    # ------------------------------------------------------------------ execution
    def execute(self, moves: List[PlannedMove], allow_similar: bool = False) -> List[PlannedMove]:
        """Execute APPROVED moves.  Similar-media moves additionally need *allow_similar*."""
        approved = [m for m in moves if m.status is MoveStatus.APPROVED]
        if not approved:
            return moves
        self.journal.lock()
        try:
            for i, mv in enumerate(approved):
                if self.cancel.cancelled:
                    mv.status, mv.reason = MoveStatus.SKIPPED, "cancelled before start (nothing changed)"
                    continue
                self.progress.update(f"relocating: {i + 1}/{len(approved)}")
                if mv.match_class is not MatchClass.EXACT and not allow_similar:
                    mv.status = MoveStatus.SKIPPED
                    mv.reason = "similar-media match requires explicit approval"
                    continue
                try:
                    self._execute_one(mv)
                except JournalError as exc:
                    # Without a working journal no further move is safe.
                    mv.status = MoveStatus.FAILED
                    mv.reason = f"transaction journal unavailable ({exc}); source retained"
                    self.cancel.cancel()
        finally:
            self.journal.unlock()
            self.progress.done()
        return moves

    def _skip(self, mv: PlannedMove, reason: str) -> None:
        mv.status, mv.reason, mv.timestamp = MoveStatus.SKIPPED, reason, now_iso()

    def _execute_one(self, mv: PlannedMove) -> None:
        src, orig = mv.source, mv.original
        cfg = self.cfg
        mv.timestamp = now_iso()

        # -- 1. source is a regular file inside an explicitly included root --
        if not any(is_within(src.path, r) for r in self.roots) or not any(
                os.path.normcase(str(src.root)) == os.path.normcase(str(r)) for r in self.roots):
            return self._skip(mv, "source is not inside an included scan root")
        if is_within(src.path, self.destination):
            return self._skip(mv, "source is inside the Duplicates destination")
        try:
            sst = os.lstat(src.path)
        except OSError as exc:
            return self._skip(mv, f"source no longer accessible: {exc}")
        if not stat.S_ISREG(sst.st_mode):
            return self._skip(mv, "source is no longer a regular file")
        # -- 2. unchanged since scan --
        if not _same_content_state(StatFingerprint.from_stat(sst), src.fingerprint):
            return self._skip(mv, "source changed since it was scanned")
        # -- original must exist and be a different file --
        try:
            ost = os.lstat(orig.path)
        except OSError as exc:
            return self._skip(mv, f"retained original no longer accessible: {exc}")
        if not stat.S_ISREG(ost.st_mode):
            return self._skip(mv, "retained original is no longer a regular file")
        if same_file(src.path, orig.path) and not cfg.hardlinks_as_duplicates:
            return self._skip(mv, "source and retained original are the same underlying file")

        # -- 3. fresh revalidation (never trusts cached hashes) --
        try:
            src_sha, src_fp = sha256_file(src.path, cfg.chunk_size, self.cancel, src.fingerprint)
            orig_sha, orig_fp = sha256_file(orig.path, cfg.chunk_size, self.cancel)
        except CancelledError:
            return self._skip(mv, "cancelled during verification (nothing changed)")
        except SourceChanged as exc:
            return self._skip(mv, str(exc))
        except OSError as exc:
            return self._skip(mv, f"re-verification failed: {exc}")
        if mv.match_class is MatchClass.EXACT:
            group_sha = src.sha256
            if src_sha != group_sha or orig_sha != group_sha:
                return self._skip(mv, "content no longer matches the retained original")
            if cfg.verify == "bytes":
                try:
                    if not files_identical(src.path, orig.path, cfg.chunk_size, self.cancel):
                        return self._skip(mv, "byte-for-byte comparison failed")
                except (OSError, SourceChanged, CancelledError) as exc:
                    return self._skip(mv, f"byte comparison could not complete: {exc}")
        # Similar-media moves (user-approved) cannot be "re-proven" equal; the
        # checks above guarantee the original still exists and is unchanged,
        # and the copy below is verified against the source's own fresh hash.

        # -- 4. destination containment --
        d_dir = self.destination_dir(src)
        try:
            assert_within(d_dir, self.destination, "destination directory")
            self.destination.mkdir(parents=True, exist_ok=True)
            # create each level and re-check, so a planted symlink cannot redirect us
            d_dir.mkdir(parents=True, exist_ok=True)
            assert_within(d_dir, self.destination, "destination directory")
        except (OSError, SafetyViolation) as exc:
            return self._skip(mv, f"destination unusable: {exc}")

        # -- 5. intent --
        tx = new_tx_id()
        mv.tx_id = tx
        self.journal.append(tx, "intent", kind="move", scan_id=self.scan_id, group_id=mv.group_id,
                            match_class=mv.match_class.value, source=str(src.path), root=str(src.root),
                            original=str(orig.path), original_sha256=orig_sha, sha256=src_sha, size=src_fp.size,
                            src_fp=[src_fp.dev, src_fp.ino, src_fp.size, src_fp.mtime_ns],
                            orig_fp=[orig_fp.dev, orig_fp.ino, orig_fp.size, orig_fp.mtime_ns],
                            dest_dir=str(d_dir), filename=src.path.name)
        self.db.record_operation(tx, self.scan_id, "move", str(src.path), None, str(orig.path), src_sha,
                                 src_fp.size, "started")

        # -- 6-8. reserve, transfer, verify --
        preferred = mv.destination.name if mv.destination and mv.destination.parent == d_dir else None
        names = candidate_names(src.path.name)
        if preferred:
            names = _prepend(preferred, names)
        try:
            # cancel=None: once a transaction has started it is finished, so a
            # Ctrl+C never leaves a half-written copy behind.
            result = reserve_and_transfer(src.path, d_dir, names, src_sha, src_fp.size, self.journal, tx,
                                          cfg.chunk_size, None, link_func=self._link_func)
            assert_within(result.destination, self.destination, "destination file")
        except (OSError, SafetyViolation, CancelledError) as exc:
            reserved = self._reserved_dest(tx)
            note = f"; incomplete copy left at {reserved} (safe to remove manually)" if reserved else ""
            self.journal.append(tx, "failed", reason=str(exc), state="source_retained",
                                incomplete_destination=str(reserved) if reserved else None)
            self.db.record_operation(tx, self.scan_id, "move", str(src.path), str(reserved) if reserved else None,
                                     str(orig.path), src_sha, src_fp.size, "failed", str(exc))
            mv.status, mv.reason = MoveStatus.FAILED, f"{exc}{note}; source retained"
            return
        mv.destination = result.destination
        self.journal.append(tx, "dest_verified", destination=str(result.destination), method=result.method)

        # -- 9-10. final checks and source removal --
        try:
            _remove_source_after_verified_move(src.path, src_fp, result.destination, src_fp.size, orig.path,
                                               orig_fp, allow_retained_same_inode=cfg.hardlinks_as_duplicates)
        except (OSError, SafetyViolation) as exc:
            self.journal.append(tx, "failed", reason=f"source not removed: {exc}", state="both_present",
                                destination=str(result.destination))
            self.db.record_operation(tx, self.scan_id, "move", str(src.path), str(result.destination),
                                     str(orig.path), src_sha, src_fp.size, "incomplete", str(exc))
            mv.status = MoveStatus.INCOMPLETE
            mv.reason = (f"verified copy placed at destination but the source could not be removed ({exc}); "
                         "both copies retained")
            return
        self.journal.append(tx, "source_removed")
        self.journal.append(tx, "committed", destination=str(result.destination), method=result.method)
        self.db.record_operation(tx, self.scan_id, "move", str(src.path), str(result.destination), str(orig.path),
                                 src_sha, src_fp.size, "committed", result.method)
        mv.status, mv.reason = MoveStatus.MOVED, f"verified ({result.method})"

    def _reserved_dest(self, tx: str) -> Optional[Path]:
        t = self.journal.transactions().get(tx)
        if t is None:
            return None
        d = t.value("destination")
        return Path(d) if d else None


def _prepend(first: str, rest: Iterator[str]) -> Iterator[str]:
    yield first
    for n in rest:
        if n != first:
            yield n


def _planned(g: DuplicateGroup, dup: FileRecord, proposal: Optional[Path]) -> PlannedMove:
    mv = PlannedMove(group_id=g.group_id, match_class=g.match_class, source=dup, original=g.original,
                     destination=proposal, status=MoveStatus.PLANNED)
    if proposal is None:
        mv.status = MoveStatus.SKIPPED
        mv.reason = "no free destination name"
    return mv
