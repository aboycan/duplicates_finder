"""Similarity detector interface and grouping helpers.

Similarity detectors are optional plugins, completely separate from the exact
engine.  They can only ever produce :attr:`MatchClass.PROBABLE` or
:attr:`MatchClass.REVIEW` results, which are never moved without explicit
per-item approval.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..config import Config
from ..models import DuplicateGroup, FileRecord, IssueKind, MatchClass, MediaCategory, ScanIssue
from ..runtime import CancelToken, Progress


@dataclass
class SimilarityMatch:
    a: FileRecord
    b: FileRecord
    match_class: MatchClass
    score: float                      # 0..1, higher = more similar
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.match_class is MatchClass.EXACT:
            raise ValueError("similarity detectors may not produce exact matches")


class SimilarityDetector(ABC):
    name: str = ""
    categories: Set[MediaCategory] = set()

    def __init__(self, cfg: Config, cancel: Optional[CancelToken] = None, progress: Optional[Progress] = None):
        self.cfg = cfg
        self.cancel = cancel or CancelToken()
        self.progress = progress or Progress(False)
        self.issues: List[ScanIssue] = []

    @abstractmethod
    def available(self) -> Tuple[bool, str]:
        """``(True, "")`` if usable, else ``(False, reason)``."""

    @abstractmethod
    def find_matches(self, records: Sequence[FileRecord]) -> List[SimilarityMatch]:
        """Return pairwise matches among *records* (already filtered by category)."""

    def _issue(self, path: Path, message: str, kind: IssueKind = IssueKind.CORRUPT) -> None:
        self.issues.append(ScanIssue(path, kind, f"[{self.name}] {message}"))


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def build_groups(matches: List[SimilarityMatch], cfg: Config, roots: List[Path]) -> List[DuplicateGroup]:
    """Union-find over pairwise matches; a group is as weak as its weakest link."""
    from ..grouping import select_original

    parent: Dict[int, int] = {}
    recs: Dict[int, FileRecord] = {}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for m in matches:
        for r in (m.a, m.b):
            if id(r) not in parent:
                parent[id(r)] = id(r)
                recs[id(r)] = r
        ra, rb = find(id(m.a)), find(id(m.b))
        if ra != rb:
            parent[ra] = rb

    clusters: Dict[int, List[FileRecord]] = {}
    for key, rec in recs.items():
        clusters.setdefault(find(key), []).append(rec)
    by_cluster: Dict[int, List[SimilarityMatch]] = {}
    for m in matches:
        by_cluster.setdefault(find(id(m.a)), []).append(m)

    groups: List[DuplicateGroup] = []
    for root_id, members in clusters.items():
        if len(members) < 2:
            continue
        ms = by_cluster.get(root_id, [])
        weakest = MatchClass.REVIEW if any(m.match_class is MatchClass.REVIEW for m in ms) else MatchClass.PROBABLE
        # Transitive clusters (A~B, B~C) are only as strong as an explicit link; flag them for review.
        if len(members) > 2 and len(ms) < len(members) * (len(members) - 1) // 2:
            weakest = MatchClass.REVIEW
        original, dups, reason = select_original(members, cfg, roots)
        gid = "S-" + hashlib.sha256("|".join(sorted(str(m.path) for m in members)).encode(
            "utf-8", "surrogatepass")).hexdigest()[:12]
        groups.append(DuplicateGroup(
            group_id=gid, match_class=weakest, confidence=round(min(m.score for m in ms), 4) if ms else 0.0,
            category=original.category, original=original, duplicates=dups,
            verified_by=",".join(sorted({m.evidence.get("method", "?") for m in ms})),
            evidence={"pairs": [{"a": str(m.a.path), "b": str(m.b.path), "class": m.match_class.value,
                                 "score": round(m.score, 4), **{k: v for k, v in m.evidence.items()}}
                                for m in ms]},
            selection_reason=reason))
    groups.sort(key=lambda g: g.group_id)
    return groups
