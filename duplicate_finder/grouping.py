"""Exact-duplicate grouping and deterministic original selection.

Pipeline (each stage only processes survivors of the previous one):

1. group by size                      — free, from the scan
2. group by partial hash (first+last 64 KiB) — cheap pre-filter for large files
3. group by full SHA-256              — streamed in chunks, cached when safe
4. optional byte-for-byte comparison  — ``verify = "bytes"``

Only stage 3 (or 4) establishes membership; stages 1-2 only rule files out.
"""

from __future__ import annotations

import hashlib
import os
import sys
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, TypeVar

from .config import Config
from .database import Database
from .errors import CancelledError, SourceChanged
from .hashing import PARTIAL_BLOCK, files_identical, partial_hash, sha256_file
from .models import DuplicateGroup, FileRecord, IssueKind, MatchClass, ScanIssue
from .runtime import CancelToken, Progress
from .safety import is_within

CTIME_IS_CHANGE_TIME = not sys.platform.startswith("win")

T = TypeVar("T")
R = TypeVar("R")


def bounded_map(fn: Callable[[T], R], items: Sequence[T], workers: int,
                cancel: CancelToken) -> Iterator[Tuple[T, Optional[R], Optional[BaseException]]]:
    """Run *fn* over *items* with at most ``workers*2`` tasks in flight.

    Yields ``(item, result, exception)`` in completion order.  Keeps memory
    bounded for millions of files and stops submitting when cancelled.
    """
    if workers <= 1:
        for it in items:
            cancel.check()
            try:
                yield it, fn(it), None
            except CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reported by caller
                yield it, None, exc
        return
    limit = workers * 2
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="dupfinder") as pool:
        pending: Dict[Future, T] = {}
        iterator = iter(items)
        exhausted = False
        try:
            while True:
                while not exhausted and len(pending) < limit:
                    cancel.check()
                    try:
                        it = next(iterator)
                    except StopIteration:
                        exhausted = True
                        break
                    pending[pool.submit(fn, it)] = it
                if not pending:
                    break
                done, _ = wait(list(pending), return_when=FIRST_COMPLETED)
                for fut in done:
                    it = pending.pop(fut)
                    exc = fut.exception()
                    if isinstance(exc, CancelledError):
                        raise exc
                    yield it, (None if exc else fut.result()), exc
        finally:
            for fut in pending:
                fut.cancel()


# ---------------------------------------------------------------------- original selection

def _sort_key(rec: FileRecord, criterion: str, cfg: Config, roots: List[Path]):
    if criterion == "prefer-paths":
        return 0 if any(is_within(rec.path, p) for p in cfg.prefer_paths) else 1
    if criterion == "root-order":
        for i, r in enumerate(roots):
            if os.path.normcase(str(rec.root)) == os.path.normcase(str(r)):
                return i
        return len(roots)
    if criterion == "oldest":
        return rec.fingerprint.mtime_ns
    if criterion == "newest":
        return -rec.fingerprint.mtime_ns
    if criterion == "shortest-path":
        return len(rec.path.parts)
    if criterion == "shortest-name":
        return len(rec.path.name)
    if criterion == "longest-name":
        return -len(rec.path.name)
    if criterion == "path":
        return os.path.normcase(str(rec.path))
    raise ValueError(criterion)


def select_original(members: List[FileRecord], cfg: Config, roots: List[Path]) -> Tuple[FileRecord, List[FileRecord], str]:
    """Deterministically choose the copy to keep.

    The rule is a lexicographic sort over ``cfg.keep`` criteria, always ending
    with the full path so the outcome never depends on scan order.  Returns
    ``(original, others, reason)``.
    """
    criteria = list(cfg.keep)
    if "path" not in criteria:
        criteria.append("path")
    ordered = sorted(members, key=lambda r: tuple(_sort_key(r, c, cfg, roots) for c in criteria))
    original, others = ordered[0], ordered[1:]
    reason = "only candidate"
    if others:
        runner = others[0]
        for c in criteria:
            if _sort_key(original, c, cfg, roots) != _sort_key(runner, c, cfg, roots):
                reason = f"kept by rule '{c}'"
                break
    return original, others, reason


# ---------------------------------------------------------------------- exact matcher

class ExactMatcher:
    def __init__(self, cfg: Config, db: Database, roots: List[Path], issues: List[ScanIssue],
                 cancel: Optional[CancelToken] = None, progress: Optional[Progress] = None):
        self.cfg = cfg
        self.db = db
        self.roots = roots
        self.issues = issues
        self.cancel = cancel or CancelToken()
        self.progress = progress or Progress(False)
        self.stats = {"candidates": 0, "partial_hashed": 0, "full_hashed": 0, "cache_hits": 0,
                      "byte_compared": 0, "bytes_hashed": 0}

    def _issue(self, rec: FileRecord, exc: BaseException) -> None:
        if isinstance(exc, SourceChanged):
            kind = IssueKind.CHANGED
        elif isinstance(exc, PermissionError):
            kind = IssueKind.PERMISSION
        else:
            kind = IssueKind.UNREADABLE
        self.issues.append(ScanIssue(rec.path, kind, str(exc)))

    def find(self, records: Iterable[FileRecord]) -> List[DuplicateGroup]:
        by_size: Dict[int, List[FileRecord]] = defaultdict(list)
        for r in records:
            by_size[r.size].append(r)
        candidates = [g for g in by_size.values() if len(g) > 1]
        self.stats["candidates"] = sum(len(g) for g in candidates)

        # Stage 2: partial hash for files large enough for it to matter.
        stage3: List[List[FileRecord]] = []
        need_partial: List[FileRecord] = []
        for g in candidates:
            if g[0].size > 4 * PARTIAL_BLOCK:
                need_partial.extend(g)
            else:
                stage3.append(g)
        partials: Dict[int, str] = {}
        if need_partial:
            pending_cache = []

            def do_partial(rec: FileRecord) -> Tuple[str, bool]:
                cached_partial, _ = self.db.get_cached(rec.path, rec.fingerprint) if self.cfg.use_cache else (None, None)
                if cached_partial:
                    return cached_partial, True
                return partial_hash(rec.path, rec.fingerprint), False

            for i, (rec, res, exc) in enumerate(bounded_map(do_partial, need_partial, self.cfg.workers, self.cancel)):
                if exc is not None:
                    self._issue(rec, exc)
                    continue
                value, cached = res  # type: ignore[misc]
                partials[id(rec)] = value
                if not cached:
                    self.stats["partial_hashed"] += 1
                    pending_cache.append((rec.path, rec.fingerprint, value, None))
                self.progress.update(f"pre-filtering: {i + 1}/{len(need_partial)}")
            self.db.put_hashes(pending_cache)
            regroup: Dict[Tuple[int, str], List[FileRecord]] = defaultdict(list)
            for rec in need_partial:
                if id(rec) in partials:
                    regroup[(rec.size, partials[id(rec)])].append(rec)
            stage3.extend(g for g in regroup.values() if len(g) > 1)

        # Stage 3: full SHA-256.
        to_hash = [r for g in stage3 for r in g]
        pending_cache = []

        def do_full(rec: FileRecord) -> Tuple[str, bool]:
            # A cached full hash is only trusted where ctime is a kernel-maintained
            # change time (POSIX).  On Windows st_ctime is the *creation* time,
            # so size+mtime (which tools can reset) would be the only guard.
            if self.cfg.use_cache and CTIME_IS_CHANGE_TIME:
                _, sha = self.db.get_cached(rec.path, rec.fingerprint)
                if sha:
                    return sha, True
            digest, _ = sha256_file(rec.path, self.cfg.chunk_size, self.cancel, rec.fingerprint)
            return digest, False

        hashed_bytes = 0
        total_bytes = sum(r.size for r in to_hash) or 1
        for rec, res, exc in bounded_map(do_full, to_hash, self.cfg.workers, self.cancel):
            if exc is not None:
                self._issue(rec, exc)
                continue
            digest, cached = res  # type: ignore[misc]
            rec.sha256 = digest
            rec.hash_source = "cache" if cached else "fresh"
            if cached:
                self.stats["cache_hits"] += 1
            else:
                self.stats["full_hashed"] += 1
                self.stats["bytes_hashed"] += rec.size
                pending_cache.append((rec.path, rec.fingerprint, partials.get(id(rec)), digest))
            hashed_bytes += rec.size
            self.progress.update(f"hashing: {hashed_bytes * 100 // total_bytes}% "
                                 f"({hashed_bytes / 1048576:.1f} MiB)")
            if len(pending_cache) >= 500:
                self.db.put_hashes(pending_cache)
                pending_cache = []
        self.db.put_hashes(pending_cache)

        by_hash: Dict[Tuple[int, str], List[FileRecord]] = defaultdict(list)
        for rec in to_hash:
            if rec.sha256:
                by_hash[(rec.size, rec.sha256)].append(rec)

        groups: List[DuplicateGroup] = []
        for (size, digest), members in sorted(by_hash.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            if len(members) < 2:
                continue
            clusters = [members]
            verified_by = "sha256"
            if self.cfg.verify == "bytes":
                clusters = self._byte_verify(members)
                verified_by = "sha256+bytes"
            for cluster in clusters:
                if len(cluster) < 2:
                    continue
                original, dups, reason = select_original(cluster, self.cfg, self.roots)
                gid = "X-" + hashlib.sha256(
                    (digest + "|" + "|".join(sorted(str(m.path) for m in cluster))).encode("utf-8", "surrogatepass")
                ).hexdigest()[:12]
                any_cached = any(m.hash_source == "cache" for m in cluster)
                groups.append(DuplicateGroup(
                    group_id=gid,
                    match_class=MatchClass.EXACT,
                    confidence=1.0,
                    category=original.category,
                    original=original,
                    duplicates=dups,
                    sha256=digest,
                    verified_by=verified_by + (" (some hashes from validated cache; re-hashed before any move)"
                                               if any_cached and verified_by == "sha256" else ""),
                    evidence={"size": size},
                    selection_reason=reason,
                ))
        self.progress.done()
        return groups

    def _byte_verify(self, members: List[FileRecord]) -> List[List[FileRecord]]:
        """Split a hash group into clusters that are byte-for-byte identical."""
        clusters: List[List[FileRecord]] = []
        for rec in members:
            self.cancel.check()
            placed = False
            for cluster in clusters:
                try:
                    self.stats["byte_compared"] += 1
                    if files_identical(cluster[0].path, rec.path, self.cfg.chunk_size, self.cancel):
                        cluster.append(rec)
                        placed = True
                        break
                except (OSError, SourceChanged) as exc:
                    self._issue(rec, exc)
                    placed = True  # excluded from all clusters
                    break
            if not placed:
                clusters.append([rec])
        return clusters
