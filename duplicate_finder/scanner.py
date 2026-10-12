"""Directory traversal and file discovery.

Rules enforced here:

* Only the explicitly supplied roots are traversed.
* The ``Duplicates`` destination and the application's state directory are
  never traversed, even when they live inside a scan root (identity-based, so
  case or symlink spelling differences cannot defeat the check).
* Symbolic links are skipped by default and reported.  With
  ``symlink_policy = "follow-within-roots"`` directory links are followed only
  when their target lies inside a scan root, and file links are recorded under
  their *target* path so a link is never mistaken for an independent copy.
* Hard links to the same inode are collapsed into one record (``aliases``)
  unless ``hardlinks_as_duplicates`` is enabled.
* Nothing is silently skipped: every unreadable entry becomes a ScanIssue.
"""

from __future__ import annotations

import fnmatch
import os
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .config import Config
from .errors import ConfigError
from .models import FileRecord, IssueKind, ScanIssue, StatFingerprint
from .runtime import CancelToken, Progress
from .safety import absolute, is_within, resolved


@dataclass
class ScanResult:
    records: List[FileRecord] = field(default_factory=list)
    issues: List[ScanIssue] = field(default_factory=list)
    dirs_scanned: int = 0
    files_seen: int = 0


_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT
_IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003


def _is_junction(entry: "os.DirEntry[str]") -> bool:
    """Windows directory junctions / mount points are treated like symlinks."""
    if os.name != "nt":
        return False
    is_junction = getattr(entry, "is_junction", None)  # Python 3.12+
    if is_junction is not None and is_junction():
        return True
    # Only mount-point reparse tags (junctions) count; OneDrive/cloud
    # placeholders are reparse points too but are ordinary files and folders.
    try:
        st = os.lstat(entry.path)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT) and \
        getattr(st, "st_reparse_tag", 0) == _IO_REPARSE_TAG_MOUNT_POINT


def _match_any(name: str, patterns: Iterable[str]) -> bool:
    name_n = os.path.normcase(name)
    return any(fnmatch.fnmatch(name_n, os.path.normcase(p)) for p in patterns)


def normalise_roots(roots: Iterable[Path]) -> Tuple[List[Path], List[str]]:
    """Validate roots, drop duplicates and roots nested inside other roots."""
    warnings: List[str] = []
    out: List[Path] = []
    for r in roots:
        p = absolute(r)
        if not p.exists():
            raise ConfigError(f"scan root does not exist: {r}")
        if not p.is_dir():
            raise ConfigError(f"scan root is not a directory: {r}")
        if any(is_within(p, existing) for existing in out):
            warnings.append(f"ignoring {p}: it is inside another scan root")
            continue
        nested = [e for e in out if is_within(e, p)]
        for e in nested:
            warnings.append(f"ignoring {e}: it is inside another scan root")
            out.remove(e)
        out.append(p)
    return out, warnings


class Scanner:
    def __init__(self, cfg: Config, excluded_dirs: Iterable[Path] = (),
                 cancel: Optional[CancelToken] = None, progress: Optional[Progress] = None):
        self.cfg = cfg
        self.cancel = cancel or CancelToken()
        self.progress = progress or Progress(False)
        self.roots, self.warnings = normalise_roots(cfg.roots)
        self._excluded_paths = [absolute(p) for p in excluded_dirs]
        self._excluded_ids: Set[Tuple[int, int]] = set()
        for p in self._excluded_paths:
            try:
                st = os.stat(p)
                if st.st_ino:
                    self._excluded_ids.add((st.st_dev, st.st_ino))
            except OSError:
                pass

    # ------------------------------------------------------------------ helpers
    def _is_excluded_dir(self, path: Path, st: Optional[os.stat_result]) -> bool:
        if st is not None and st.st_ino and (st.st_dev, st.st_ino) in self._excluded_ids:
            return True
        return any(is_within(path, ex) for ex in self._excluded_paths)

    def _root_for(self, path: Path) -> Optional[Path]:
        for r in self.roots:
            if is_within(path, r):
                return r
        return None

    # ------------------------------------------------------------------ main
    def scan(self) -> ScanResult:
        res = ScanResult()
        by_identity: Dict[Tuple[int, int], FileRecord] = {}
        visited_dirs: Set[Tuple[int, int]] = set()
        now = time.time()

        for root in self.roots:
            stack: List[Tuple[Path, Path]] = [(root, root)]
            while stack:
                self.cancel.check()
                directory, logical_root = stack.pop()
                try:
                    dst = os.stat(directory)
                except OSError as exc:
                    res.issues.append(ScanIssue(directory, IssueKind.UNREADABLE, str(exc)))
                    continue
                if self._is_excluded_dir(directory, dst):
                    continue
                if dst.st_ino:
                    key = (dst.st_dev, dst.st_ino)
                    if key in visited_dirs:
                        continue  # loop via symlink or bind mount
                    visited_dirs.add(key)
                res.dirs_scanned += 1
                try:
                    with os.scandir(directory) as it:
                        entries = sorted(it, key=lambda e: e.name)
                except PermissionError as exc:
                    res.issues.append(ScanIssue(directory, IssueKind.PERMISSION, str(exc)))
                    continue
                except OSError as exc:
                    res.issues.append(ScanIssue(directory, IssueKind.UNREADABLE, str(exc)))
                    continue

                subdirs: List[Tuple[Path, Path]] = []
                for entry in entries:
                    path = directory / entry.name
                    try:
                        if entry.is_symlink() or _is_junction(entry):
                            self._handle_symlink(path, logical_root, res, subdirs, by_identity, now)
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if _match_any(entry.name, self.cfg.exclude_dirs):
                                continue
                            subdirs.append((path, logical_root))
                            continue
                        if entry.is_file(follow_symlinks=False):
                            st = os.stat(path, follow_symlinks=False)
                            self._add_file(path, logical_root, st, res, by_identity, now)
                            continue
                        res.issues.append(ScanIssue(path, IssueKind.SPECIAL_FILE,
                                                    "not a regular file (device, pipe, socket ...)"))
                    except PermissionError as exc:
                        res.issues.append(ScanIssue(path, IssueKind.PERMISSION, str(exc)))
                    except FileNotFoundError as exc:
                        res.issues.append(ScanIssue(path, IssueKind.CHANGED, f"vanished during scan: {exc}"))
                    except OSError as exc:
                        res.issues.append(ScanIssue(path, IssueKind.UNREADABLE, str(exc)))
                # Depth-first in name order (reverse push so pop order is sorted).
                stack.extend(reversed(subdirs))
                self.progress.update(f"scanning: {res.dirs_scanned} dirs, {res.files_seen} files")
        return res

    def _handle_symlink(self, path: Path, logical_root: Path, res: ScanResult,
                        subdirs: List[Tuple[Path, Path]], by_identity: Dict, now: float) -> None:
        if self.cfg.symlink_policy == "skip":
            res.issues.append(ScanIssue(path, IssueKind.SYMLINK_SKIPPED, "symbolic link not followed (policy: skip)"))
            return
        target = resolved(path)
        root = self._root_for(target)
        if root is None:
            res.issues.append(ScanIssue(path, IssueKind.SYMLINK_SKIPPED,
                                        f"symbolic link target {target} is outside the scan roots"))
            return
        try:
            st = os.stat(target, follow_symlinks=False)
        except OSError as exc:
            res.issues.append(ScanIssue(path, IssueKind.UNREADABLE, f"broken symbolic link: {exc}"))
            return
        if stat.S_ISDIR(st.st_mode):
            if not _match_any(target.name, self.cfg.exclude_dirs):
                subdirs.append((target, root))
        elif stat.S_ISREG(st.st_mode):
            # Record the *target*; identity de-duplication makes the link an alias.
            self._add_file(target, root, st, res, by_identity, now, via_link=path)
        else:
            res.issues.append(ScanIssue(path, IssueKind.SPECIAL_FILE, "link to a non-regular file"))

    def _add_file(self, path: Path, root: Path, st: os.stat_result, res: ScanResult,
                  by_identity: Dict, now: float, via_link: Optional[Path] = None) -> None:
        res.files_seen += 1
        if _match_any(path.name, self.cfg.exclude_files):
            return
        size = st.st_size
        if size < self.cfg.min_size or (self.cfg.max_size is not None and size > self.cfg.max_size):
            return
        if self.cfg.stability_seconds > 0 and now - st.st_mtime < self.cfg.stability_seconds:
            res.issues.append(ScanIssue(path, IssueKind.UNSTABLE,
                                        f"modified less than {self.cfg.stability_seconds:g}s ago; skipped"))
            return
        fp = StatFingerprint.from_stat(st)
        if fp.has_identity():
            key = fp.identity
            existing = by_identity.get(key)
            if existing is not None:
                alias = via_link or path
                if via_link is not None or not self.cfg.hardlinks_as_duplicates:
                    if alias != existing.path:
                        existing.aliases.append(alias)
                        kind = IssueKind.SYMLINK_SKIPPED if via_link else IssueKind.HARDLINK
                        res.issues.append(ScanIssue(alias, kind, f"same underlying file as {existing.path}"))
                    return
        rec = FileRecord(path=path, root=root, fingerprint=fp)
        if fp.has_identity() and fp.identity not in by_identity:
            by_identity[fp.identity] = rec
        res.records.append(rec)
