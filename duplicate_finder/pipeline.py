"""End-to-end orchestration: scan -> classify -> match -> plan -> (approve) -> move -> report."""

from __future__ import annotations

import datetime as _dt
import logging
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .config import Config
from .database import Database
from .detectors import build_groups, detector_classes
from .errors import CancelledError, ConfigError, SafetyViolation
from .file_types import HandlerRegistry, default_registry
from .grouping import ExactMatcher, bounded_map
from .models import (DuplicateGroup, FileRecord, IssueKind, MatchClass, MoveStatus, PlannedMove, ScanIssue)
from .organizer import Organizer
from .reporting import build_report, write_reports
from .runtime import CancelToken, Progress
from .safety import absolute, check_destination_root, is_within
from .scanner import Scanner
from .transaction_log import Journal, now_iso

log = logging.getLogger("duplicate_finder")

Approver = Callable[[List[PlannedMove], List[DuplicateGroup]], bool]


@dataclass
class RunResult:
    scan_id: str
    action: str
    mode: str
    roots: List[Path]
    destination: Path
    started: str
    finished: str = ""
    files_scanned: int = 0
    exact_groups: List[DuplicateGroup] = field(default_factory=list)
    similar_groups: List[DuplicateGroup] = field(default_factory=list)
    moves: List[PlannedMove] = field(default_factory=list)
    issues: List[ScanIssue] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    detector_status: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    report_paths: Dict[str, Path] = field(default_factory=dict)
    cancelled: bool = False

    @property
    def failures(self) -> List[PlannedMove]:
        return [m for m in self.moves if m.status in (MoveStatus.FAILED, MoveStatus.INCOMPLETE)]


def new_scan_id() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


class Engine:
    def __init__(self, cfg: Config, registry: Optional[HandlerRegistry] = None,
                 cancel: Optional[CancelToken] = None, progress: Optional[Progress] = None):
        cfg.validate()
        self.cfg = cfg
        self.registry = registry or default_registry()
        if cfg.plugins:
            self.registry.load_plugin_modules(cfg.plugins)
        self.cancel = cancel or CancelToken()
        self.progress = progress or Progress(cfg.progress)

    # ------------------------------------------------------------------ stages
    def _classify(self, records: List[FileRecord], issues: List[ScanIssue]) -> List[FileRecord]:
        reg = self.registry
        validate = self.cfg.validate_media

        def work(rec: FileRecord):
            info = reg.detect(rec.path)
            problem = None
            if validate and info.handler:
                h = reg.get(info.handler)
                if h is not None:
                    problem = h.validate(rec.path, info.format)
            return info, problem

        kept: List[FileRecord] = []
        wanted = set(self.cfg.categories)
        for i, (rec, res, exc) in enumerate(bounded_map(work, records, self.cfg.workers, self.cancel)):
            if exc is not None:
                kind = IssueKind.PERMISSION if isinstance(exc, PermissionError) else IssueKind.UNREADABLE
                issues.append(ScanIssue(rec.path, kind, f"cannot read file header: {exc}"))
                continue
            info, problem = res  # type: ignore[misc]
            rec.type_info = info
            if info.detected_by == "none":
                issues.append(ScanIssue(rec.path, IssueKind.UNKNOWN_TYPE,
                                        "unrecognised format (still eligible for exact matching as 'other')"))
            elif info.detected_by == "extension":
                issues.append(ScanIssue(rec.path, IssueKind.UNKNOWN_TYPE,
                                        f"no known signature; type '{info.format}' assumed from extension "
                                        "(file may be corrupt or truncated)"))
            if info.extension_mismatch:
                issues.append(ScanIssue(rec.path, IssueKind.EXTENSION_MISMATCH,
                                        f"content is {info.format} but extension is '{info.extension}'"))
            if problem:
                issues.append(ScanIssue(rec.path, IssueKind.CORRUPT, problem))
            if info.category.value in wanted:
                kept.append(rec)
            self.progress.update(f"identifying types: {i + 1}/{len(records)}")
        return kept

    def _similarity(self, records: List[FileRecord], exact: List[DuplicateGroup], roots: List[Path],
                    result: RunResult) -> List[DuplicateGroup]:
        surplus = {id(d) for g in exact for d in g.duplicates}
        pool = [r for r in records if id(r) not in surplus]
        matches = []
        for cls in detector_classes():
            det = cls(self.cfg, self.cancel, self.progress)
            subset = [r for r in pool if r.category in det.categories]
            ok, why = det.available()
            if not ok:
                result.detector_status[det.name] = f"unavailable: {why}"
                continue
            if not subset:
                result.detector_status[det.name] = "no files"
                continue
            found = det.find_matches(subset)
            result.issues.extend(det.issues)
            result.detector_status[det.name] = f"analysed {len(subset)} files, {len(found)} similar pairs"
            matches.extend(found)
        return build_groups(matches, self.cfg, roots)

    # ------------------------------------------------------------------ run
    def run(self, approver: Optional[Approver] = None) -> RunResult:
        cfg = self.cfg
        scan_id = new_scan_id()
        destination = absolute(cfg.effective_destination())
        result = RunResult(scan_id=scan_id, action=cfg.action, mode=cfg.mode, roots=[],
                           destination=destination, started=now_iso())

        excluded = [destination, absolute(cfg.state_dir), absolute(cfg.effective_report_dir)]
        scanner = Scanner(cfg, excluded, self.cancel, self.progress)
        roots = scanner.roots
        result.roots = roots
        result.warnings.extend(scanner.warnings)
        problem = check_destination_root(destination, roots)
        if problem:
            raise ConfigError(f"unsafe destination: {problem}")
        for r in roots:
            if is_within(destination, r):
                result.warnings.append(f"destination {destination} is inside scan root {r}; "
                                       "it is excluded from scanning")

        journal = Journal(cfg.journal_path)
        if cfg.action in ("interactive", "auto"):
            pending = journal.incomplete()
            if pending:
                raise SafetyViolation(f"{len(pending)} interrupted operation(s) found in the journal; "
                                      "run 'duplicate_finder recover' first")

        db = Database(cfg.db_path, enabled=True)
        if db.recovered_from_corruption:
            result.warnings.append(f"state database was corrupt and was moved aside to "
                                   f"{db.recovered_from_corruption}; a new one was created")
        try:
            db.start_scan(scan_id, roots, cfg.mode, cfg.action)
            status = "completed"
            try:
                self._run_stages(result, scanner, roots, db, journal, destination, approver)
            except CancelledError:
                result.cancelled = True
                status = "cancelled"
            result.finished = now_iso()
            report = build_report(result, cfg.redact_paths)
            if cfg.report_formats:
                result.report_paths = write_reports(report, cfg.effective_report_dir, cfg.report_formats)
            db.finish_scan(scan_id, status, report["summary"])
        finally:
            db.close()
        return result

    def _run_stages(self, result: RunResult, scanner: Scanner, roots: List[Path], db: Database,
                    journal: Journal, destination: Path, approver: Optional[Approver]) -> None:
        cfg = self.cfg
        scan = scanner.scan()
        result.issues.extend(scan.issues)
        result.files_scanned = len(scan.records)
        self.progress.done(f"scanned {scan.dirs_scanned} folders, {len(scan.records)} files")

        records = self._classify(scan.records, result.issues)
        self.progress.done()

        exact: List[DuplicateGroup] = []
        if cfg.mode in ("exact", "all"):
            matcher = ExactMatcher(cfg, db, roots, result.issues, self.cancel, self.progress)
            exact = matcher.find(records)
            result.stats.update(matcher.stats)
        result.exact_groups = exact

        if cfg.mode in ("similarity", "all"):
            result.similar_groups = self._similarity(records, exact, roots, result)
            self.progress.done()

        organizer = Organizer(cfg, db, journal, result.scan_id, roots, destination, self.cancel, self.progress)
        moves = organizer.plan(result.exact_groups + result.similar_groups)
        result.moves = moves
        for mv in moves:
            if mv.status is MoveStatus.PLANNED and not mv.match_class.auto_movable:
                mv.reason = "similar media: requires explicit approval"

        if cfg.action in ("dry-run", "report"):
            return
        if cfg.action == "auto":
            for mv in moves:
                if mv.status is MoveStatus.PLANNED and mv.match_class is MatchClass.EXACT:
                    mv.status = MoveStatus.APPROVED
            organizer.execute(moves, allow_similar=False)
        elif cfg.action == "interactive":
            if approver is None:
                raise ConfigError("interactive mode needs an approver")
            if approver(moves, result.exact_groups + result.similar_groups):
                organizer.execute(moves, allow_similar=True)
            else:
                for mv in moves:
                    if mv.status is MoveStatus.APPROVED:
                        mv.status, mv.reason = MoveStatus.REJECTED, "not confirmed"
        for mv in moves:
            log.info("move %s %s -> %s: %s %s", mv.group_id, mv.source.path, mv.destination, mv.status.value,
                     mv.reason)
