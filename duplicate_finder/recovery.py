"""Crash recovery, restore and the relocation manifest.

Recovery never deletes data.  For each journaled transaction that did not
reach a terminal state it inspects the source and destination and either

* **resumes** (default): if the destination holds a verified copy and the
  source and retained original are unchanged, the move is completed through
  the same guarded removal function used by normal moves; or
* **rolls back** (``--rollback``): the source is left where it is and the
  transaction is closed; any destination copy is reported (an extra copy is
  never data loss).

Restore moves relocated files back to their original paths using the same
no-overwrite, verify-before-remove transfer.  If the original path is now
occupied, both files are kept and the item is reported as a conflict unless
an alternative restore directory is supplied.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .database import Database
from .errors import CancelledError, SafetyViolation, SourceChanged
from .hashing import sha256_file
from .models import StatFingerprint
from .organizer import (_remove_source_after_verified_move, candidate_names, reserve_and_transfer)
from .runtime import CancelToken
from .safety import absolute, assert_within, is_within, safe_relative, same_file
from .transaction_log import Journal, Transaction, new_tx_id


@dataclass
class RecoveryItem:
    tx_id: str
    kind: str
    source: str
    destination: Optional[str]
    outcome: str
    detail: str = ""
    critical: bool = False


@dataclass
class RecoveryReport:
    items: List[RecoveryItem] = field(default_factory=list)

    @property
    def critical(self) -> List[RecoveryItem]:
        return [i for i in self.items if i.critical]


def _fp_tuple(path: Path) -> Optional[tuple]:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    fp = StatFingerprint.from_stat(st)
    return (fp.dev, fp.ino, fp.size, fp.mtime_ns)


def _hash_or_none(path: Path, chunk: int) -> Optional[str]:
    try:
        return sha256_file(path, chunk)[0]
    except (OSError, SourceChanged):
        return None


def _orphan_links(tx: Transaction, source: Path) -> List[str]:
    """Destination names that are hard links of *source* but were never journaled."""
    intent = tx.intent
    d_dir, fname = intent.get("dest_dir"), intent.get("filename")
    if not d_dir or not fname or not source.exists():
        return []
    found = []
    for i, name in enumerate(candidate_names(fname)):
        if i > 200:
            break
        cand = Path(d_dir) / name
        if cand.exists() and same_file(cand, source):
            found.append(str(cand))
    return found


def recover(journal: Journal, db: Optional[Database] = None, rollback: bool = False,
            chunk_size: int = 1024 * 1024) -> RecoveryReport:
    report = RecoveryReport()
    with journal:
        for tx in journal.incomplete():
            report.items.append(_recover_one(journal, db, tx, rollback, chunk_size))
    return report


def _close(journal: Journal, db: Optional[Database], tx: Transaction, event: str, outcome: str,
           detail: str, destination: Optional[str], critical: bool = False) -> RecoveryItem:
    intent = tx.intent
    journal.append(tx.tx_id, event, outcome=outcome, detail=detail, destination=destination)
    if db is not None:
        db.record_operation(tx.tx_id, intent.get("scan_id", ""), intent.get("kind", "move"),
                            intent.get("source", ""), destination, intent.get("original"),
                            intent.get("sha256"), intent.get("size"), outcome, detail)
    return RecoveryItem(tx.tx_id, intent.get("kind", "move"), intent.get("source", ""), destination,
                        outcome, detail, critical)


def _recover_one(journal: Journal, db: Optional[Database], tx: Transaction, rollback: bool,
                 chunk: int) -> RecoveryItem:
    intent = tx.intent
    if not intent:
        return _close(journal, db, tx, "recovered_aborted", "aborted", "transaction had no intent record", None)
    source = Path(intent["source"])
    expected = intent.get("sha256")
    size = intent.get("size")
    dest_s = tx.value("destination")
    dest = Path(dest_s) if dest_s else None
    src_present = _fp_tuple(source) is not None

    if tx.has("source_removed"):
        if dest is not None and _hash_or_none(dest, chunk) == expected:
            return _close(journal, db, tx, "recovered_committed", "committed",
                          "source had been removed after verification; destination verified", dest_s)
        return _close(journal, db, tx, "recovered_aborted", "needs_attention",
                      "journal says source was removed but the destination copy does not verify", dest_s,
                      critical=True)

    if dest is None:
        orphans = _orphan_links(tx, source)
        if src_present:
            detail = "no destination was created; source untouched"
            if orphans:
                detail += f"; unjournaled hard link(s) of the source found (extra names, not data loss): {orphans}"
            return _close(journal, db, tx, "recovered_aborted", "aborted", detail, None)
        return _close(journal, db, tx, "recovered_aborted", "needs_attention",
                      "source is missing and no destination was recorded", None, critical=True)

    dest_sha = _hash_or_none(dest, chunk) if dest.exists() else None
    dest_ok = dest_sha is not None and dest_sha == expected

    if not src_present:
        if dest_ok:
            return _close(journal, db, tx, "recovered_committed", "committed",
                          "source already gone; destination holds verified content", dest_s)
        return _close(journal, db, tx, "recovered_aborted", "needs_attention",
                      "source missing and destination does not verify", dest_s, critical=True)

    # Source is present.
    if not dest_ok:
        detail = "destination incomplete or missing; source retained"
        if dest.exists():
            detail += f"; incomplete copy at {dest} can be removed manually"
        return _close(journal, db, tx, "recovered_aborted", "rolled_back", detail, dest_s)

    if rollback:
        return _close(journal, db, tx, "recovered_aborted", "rolled_back",
                      f"source retained; verified extra copy remains at {dest}", dest_s)

    # Resume: verify source and original freshly, then complete the move.
    src_sha = _hash_or_none(source, chunk)
    if src_sha != expected:
        return _close(journal, db, tx, "recovered_aborted", "rolled_back",
                      f"source changed since the move began; both kept (copy at {dest})", dest_s)
    original = intent.get("original")
    retained = Path(original) if original else None
    retained_fp = None
    if retained is not None:
        if intent.get("match_class", "exact_binary_duplicate") == "exact_binary_duplicate":
            if _hash_or_none(retained, chunk) != intent.get("original_sha256", expected):
                return _close(journal, db, tx, "recovered_aborted", "rolled_back",
                              "retained original missing or changed; source kept", dest_s)
        try:
            retained_fp = StatFingerprint.from_stat(os.lstat(retained))
        except OSError:
            return _close(journal, db, tx, "recovered_aborted", "rolled_back",
                          "retained original missing; source kept", dest_s)
    try:
        src_fp = StatFingerprint.from_stat(os.lstat(source))
        _remove_source_after_verified_move(source, src_fp, dest, size, retained, retained_fp)
    except (OSError, SafetyViolation) as exc:
        return _close(journal, db, tx, "recovered_aborted", "rolled_back",
                      f"could not complete move ({exc}); both copies kept", dest_s)
    journal.append(tx.tx_id, "source_removed")
    return _close(journal, db, tx, "recovered_committed", "committed", "move resumed and completed", dest_s)


# ---------------------------------------------------------------------- manifest / restore

@dataclass
class ManifestEntry:
    tx_id: str
    scan_id: str
    group_id: str
    match_class: str
    original_path: str
    retained_original: str
    destination: str
    sha256: str
    size: int
    timestamp: str
    restored: bool
    restored_to: Optional[str] = None


def manifest(journal: Journal) -> List[ManifestEntry]:
    txs = journal.transactions()
    restored_by: Dict[str, Transaction] = {}
    for t in txs.values():
        if t.kind == "restore" and t.committed:
            restored_by[t.intent.get("restores", "")] = t
    out = []
    for t in txs.values():
        if t.kind != "move" or not t.committed:
            continue
        i = t.intent
        r = restored_by.get(t.tx_id)
        out.append(ManifestEntry(
            tx_id=t.tx_id, scan_id=i.get("scan_id", ""), group_id=i.get("group_id", ""),
            match_class=i.get("match_class", ""), original_path=i.get("source", ""),
            retained_original=i.get("original", ""), destination=str(t.value("destination") or ""),
            sha256=i.get("sha256", ""), size=int(i.get("size") or 0), timestamp=t.events[-1]["ts"],
            restored=r is not None, restored_to=(str(r.value("destination")) if r else None)))
    out.sort(key=lambda e: e.timestamp)
    return out


@dataclass
class RestoreItem:
    move_tx: str
    from_path: str
    to_path: Optional[str]
    status: str        # restored | conflict | skipped | failed
    detail: str = ""


def restore(journal: Journal, db: Optional[Database] = None, scan_id: Optional[str] = None,
            tx_ids: Optional[List[str]] = None, restore_to: Optional[Path] = None,
            ask_new_destination: Optional[Callable[[Path, Path], Optional[Path]]] = None,
            chunk_size: int = 1024 * 1024, cancel: Optional[CancelToken] = None,
            dry_run: bool = False) -> List[RestoreItem]:
    cancel = cancel or CancelToken()
    entries = [e for e in manifest(journal) if not e.restored]
    if scan_id:
        entries = [e for e in entries if e.scan_id == scan_id]
    if tx_ids:
        wanted = set(tx_ids)
        entries = [e for e in entries if e.tx_id in wanted]
    results: List[RestoreItem] = []
    journal_txs = journal.transactions()
    with journal:
        for e in entries:
            if cancel.cancelled:
                results.append(RestoreItem(e.tx_id, e.destination, None, "skipped", "cancelled"))
                continue
            results.append(_restore_one(journal, db, e, journal_txs[e.tx_id], restore_to, ask_new_destination,
                                        chunk_size, cancel, dry_run))
    return results


def _restore_one(journal: Journal, db: Optional[Database], e: ManifestEntry, move_tx: Transaction,
                 restore_to: Optional[Path], ask: Optional[Callable[[Path, Path], Optional[Path]]],
                 chunk: int, cancel: CancelToken, dry_run: bool) -> RestoreItem:
    stored = Path(e.destination)
    target = Path(e.original_path)
    root = Path(move_tx.intent.get("root") or target.parent)
    if _fp_tuple(stored) is None:
        return RestoreItem(e.tx_id, e.destination, None, "skipped", "relocated file is no longer in Duplicates")
    sha = _hash_or_none(stored, chunk)
    if sha != e.sha256:
        return RestoreItem(e.tx_id, e.destination, None, "skipped",
                           "file in Duplicates was modified since it was moved; not restored")

    target_dir = target.parent
    names = [target.name]
    if os.path.lexists(target):
        alt: Optional[Path] = None
        if restore_to is not None:
            try:
                rel = target.relative_to(root)
            except ValueError:
                rel = Path(target.name)
            alt = absolute(restore_to) / safe_relative(rel.parent)
        elif ask is not None:
            alt = ask(target, stored)
        if alt is None:
            return RestoreItem(e.tx_id, e.destination, str(target), "conflict",
                               "original path is occupied; both files kept. Re-run with --restore-to DIR")
        target_dir = absolute(alt)
        names = list(candidate_names(target.name))
        base_for_check = absolute(restore_to) if restore_to is not None else target_dir
    else:
        base_for_check = root
    if dry_run:
        return RestoreItem(e.tx_id, e.destination, str(target_dir / names[0]), "planned")

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        assert_within(target_dir, base_for_check, "restore directory")
    except (OSError, SafetyViolation) as exc:
        return RestoreItem(e.tx_id, e.destination, str(target_dir), "skipped", f"restore directory unusable: {exc}")

    tx = new_tx_id()
    stored_fp = StatFingerprint.from_stat(os.lstat(stored))
    journal.append(tx, "intent", kind="restore", restores=e.tx_id, source=str(stored), original=None,
                   sha256=e.sha256, size=e.size, dest_dir=str(target_dir), filename=names[0],
                   src_fp=[stored_fp.dev, stored_fp.ino, stored_fp.size, stored_fp.mtime_ns])
    try:
        res = reserve_and_transfer(stored, target_dir, iter(names), e.sha256, e.size, journal, tx, chunk, cancel)
    except FileExistsError:
        journal.append(tx, "failed", reason="target appeared during restore", state="source_retained")
        return RestoreItem(e.tx_id, e.destination, str(target), "conflict", "target path became occupied")
    except (OSError, SafetyViolation, CancelledError) as exc:
        journal.append(tx, "failed", reason=str(exc), state="source_retained")
        return RestoreItem(e.tx_id, e.destination, None, "failed", f"{exc}; file kept in Duplicates")
    journal.append(tx, "dest_verified", destination=str(res.destination), method=res.method)
    try:
        _remove_source_after_verified_move(stored, stored_fp, res.destination, e.size, None, None)
    except (OSError, SafetyViolation) as exc:
        journal.append(tx, "failed", reason=f"Duplicates copy not removed: {exc}", state="both_present",
                       destination=str(res.destination))
        return RestoreItem(e.tx_id, e.destination, str(res.destination), "failed",
                           f"restored copy verified but Duplicates copy kept ({exc})")
    journal.append(tx, "source_removed")
    journal.append(tx, "committed", destination=str(res.destination), method=res.method)
    if db is not None:
        db.record_operation(tx, e.scan_id, "restore", str(stored), str(res.destination), None, e.sha256,
                            e.size, "committed")
    return RestoreItem(e.tx_id, e.destination, str(res.destination), "restored", f"verified ({res.method})")
