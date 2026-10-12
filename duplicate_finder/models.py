"""Plain data structures shared across the application."""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class MediaCategory(str, enum.Enum):
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    OTHER = "other"


class MatchClass(str, enum.Enum):
    """The three explicitly distinct outcomes required by the specification."""

    EXACT = "exact_binary_duplicate"
    PROBABLE = "probable_media_duplicate"
    REVIEW = "similar_media_requires_review"

    @property
    def auto_movable(self) -> bool:
        """Only exact binary duplicates may ever be moved without approval."""
        return self is MatchClass.EXACT


class MoveStatus(str, enum.Enum):
    PLANNED = "planned"            # proposed (dry-run / report)
    APPROVED = "approved"          # approved interactively, not yet executed
    REJECTED = "rejected"          # user declined
    MOVED = "moved"                # verified move completed
    SKIPPED = "skipped"            # refused by a safety check, nothing changed
    FAILED = "failed"              # attempted, failed, source retained
    INCOMPLETE = "incomplete"      # destination verified, source not removed


class IssueKind(str, enum.Enum):
    PERMISSION = "permission_denied"
    UNREADABLE = "unreadable"
    CHANGED = "changed_during_processing"
    UNSTABLE = "possibly_being_written"
    UNKNOWN_TYPE = "unknown_type"
    EXTENSION_MISMATCH = "extension_mismatch"
    CORRUPT = "corrupt_or_undecodable"
    SYMLINK_SKIPPED = "symlink_skipped"
    SPECIAL_FILE = "not_a_regular_file"
    HARDLINK = "hard_link_alias"
    OTHER = "other"


@dataclass(frozen=True)
class StatFingerprint:
    """Identity and change-detection fields captured from ``os.stat``.

    Equality of fingerprints is *necessary* for "unchanged" but never treated
    as *sufficient* proof of identical content: anything that leads to a move
    is re-hashed from disk first.
    """

    dev: int
    ino: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, st: os.stat_result) -> "StatFingerprint":
        return cls(
            dev=int(st.st_dev),
            ino=int(st.st_ino),
            size=int(st.st_size),
            mtime_ns=int(st.st_mtime_ns),
            ctime_ns=int(st.st_ctime_ns),
        )

    @property
    def identity(self) -> tuple:
        return (self.dev, self.ino)

    def has_identity(self) -> bool:
        # Some filesystems (FAT, certain network shares) report inode 0.
        return self.ino != 0


@dataclass
class FileTypeInfo:
    category: MediaCategory
    format: str                 # e.g. "jpeg", "mp4", "unknown"
    mime: str
    detected_by: str            # "signature" | "extension" | "none"
    extension: str              # lower-case extension incl. dot, may be ""
    extension_mismatch: bool = False
    handler: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "format": self.format,
            "mime": self.mime,
            "detected_by": self.detected_by,
            "extension": self.extension,
            "extension_mismatch": self.extension_mismatch,
            "handler": self.handler,
        }


@dataclass
class FileRecord:
    path: Path                  # absolute, as discovered (not symlink-resolved)
    root: Path                  # the scan root it was found under
    fingerprint: StatFingerprint
    type_info: Optional[FileTypeInfo] = None
    sha256: Optional[str] = None
    hash_source: str = ""       # "fresh" | "cache"
    aliases: List[Path] = field(default_factory=list)  # hard links collapsed into this record

    @property
    def size(self) -> int:
        return self.fingerprint.size

    @property
    def category(self) -> MediaCategory:
        return self.type_info.category if self.type_info else MediaCategory.OTHER

    @property
    def rel_path(self) -> Path:
        try:
            return self.path.relative_to(self.root)
        except ValueError:
            return Path(self.path.name)


@dataclass
class ScanIssue:
    path: Path
    kind: IssueKind
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {"path": str(self.path), "kind": self.kind.value, "message": self.message}


@dataclass
class DuplicateGroup:
    group_id: str
    match_class: MatchClass
    confidence: float
    category: MediaCategory
    original: FileRecord
    duplicates: List[FileRecord]
    sha256: Optional[str] = None           # exact groups only
    verified_by: str = ""                  # "sha256", "sha256+bytes", "phash", ...
    evidence: Dict[str, Any] = field(default_factory=dict)
    selection_reason: str = ""

    @property
    def members(self) -> List[FileRecord]:
        return [self.original, *self.duplicates]

    @property
    def reclaimable_bytes(self) -> int:
        return sum(d.size for d in self.duplicates)


@dataclass
class PlannedMove:
    group_id: str
    match_class: MatchClass
    source: FileRecord
    original: FileRecord
    destination: Optional[Path]
    status: MoveStatus = MoveStatus.PLANNED
    reason: str = ""
    tx_id: str = ""
    timestamp: str = ""
