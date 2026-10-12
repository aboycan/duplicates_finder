"""JSON, CSV and human-readable reports, plus the relocation manifest export.

Reports contain paths, sizes, hashes and outcomes -- never file contents.
With ``redact_paths`` the user's home directory is replaced by ``~``.
"""

from __future__ import annotations

import csv
import io
import json
import os
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from .models import DuplicateGroup, MatchClass, MoveStatus, PlannedMove
from .transaction_log import now_iso

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import RunResult

_HOME = os.path.expanduser("~")


class PathFormatter:
    def __init__(self, redact: bool = False):
        self.redact = redact

    def __call__(self, p: Any) -> Optional[str]:
        if p is None:
            return None
        s = str(p)
        if self.redact and _HOME and os.path.normcase(s).startswith(os.path.normcase(_HOME)):
            s = "~" + s[len(_HOME):]
        return s


def human_bytes(n: int) -> str:
    v = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if v < 1024 or unit == "TiB":
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.2f} {unit}"
        v /= 1024
    return f"{n} B"


def _moves_by_source(moves: List[PlannedMove]) -> Dict[str, PlannedMove]:
    return {str(m.source.path): m for m in moves}


def build_report(result: "RunResult", redact: bool = False) -> Dict[str, Any]:
    fmt = PathFormatter(redact)
    by_src = _moves_by_source(result.moves)

    def group_dict(g: DuplicateGroup) -> Dict[str, Any]:
        dups = []
        for d in g.duplicates:
            mv = by_src.get(str(d.path))
            dups.append({
                "path": fmt(d.path),
                "size": d.size,
                "sha256": d.sha256,
                "hash_source": d.hash_source,
                "destination": fmt(mv.destination) if mv else None,
                "status": mv.status.value if mv else "not_planned",
                "reason": mv.reason if mv else "",
                "tx_id": mv.tx_id if mv else "",
                "timestamp": (mv.timestamp if mv else "") or result.finished,
                "hard_link_aliases": [fmt(a) for a in d.aliases],
            })
        evidence = g.evidence
        if redact and "pairs" in evidence:
            evidence = {**evidence, "pairs": [{**p, "a": fmt(p["a"]), "b": fmt(p["b"])} for p in evidence["pairs"]]}
        return {
            "group_id": g.group_id,
            "match_class": g.match_class.value,
            "confidence": g.confidence,
            "media_type": g.category.value,
            "file_format": g.original.type_info.format if g.original.type_info else "unknown",
            "size": g.original.size,
            "sha256": g.sha256,
            "verified_by": g.verified_by,
            "original": {"path": fmt(g.original.path), "size": g.original.size, "sha256": g.original.sha256,
                         "selection_reason": g.selection_reason},
            "duplicates": dups,
            "reclaimable_bytes": g.reclaimable_bytes,
            "evidence": evidence,
        }

    statuses = Counter(m.status.value for m in result.moves)
    issue_counts = Counter(i.kind.value for i in result.issues)
    exact_dups = sum(len(g.duplicates) for g in result.exact_groups)
    return {
        "tool": "duplicate_finder",
        "scan_id": result.scan_id,
        "started": result.started,
        "finished": result.finished,
        "action": result.action,
        "mode": result.mode,
        "cancelled": result.cancelled,
        "roots": [fmt(r) for r in result.roots],
        "destination": fmt(result.destination),
        "summary": {
            "files_scanned": result.files_scanned,
            "candidate_files": result.stats.get("candidates", 0),
            "exact_groups": len(result.exact_groups),
            "exact_duplicate_copies": exact_dups,
            "exact_reclaimable_bytes": sum(g.reclaimable_bytes for g in result.exact_groups),
            "probable_media_groups": sum(1 for g in result.similar_groups if g.match_class is MatchClass.PROBABLE),
            "review_media_groups": sum(1 for g in result.similar_groups if g.match_class is MatchClass.REVIEW),
            "move_status": dict(statuses),
            "moved_bytes": sum(m.source.size for m in result.moves if m.status is MoveStatus.MOVED),
            "issues": dict(issue_counts),
            "hashing": result.stats,
        },
        "detectors": result.detector_status,
        "warnings": result.warnings,
        "exact_groups": [group_dict(g) for g in result.exact_groups],
        "similar_groups": [group_dict(g) for g in result.similar_groups],
        "issues": [{"path": fmt(i.path), "kind": i.kind.value, "message": i.message} for i in result.issues],
    }


CSV_FIELDS = ["group_id", "match_class", "confidence", "media_type", "role", "path", "size", "sha256",
              "destination", "status", "reason", "tx_id", "timestamp"]


def report_csv(report: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=CSV_FIELDS, lineterminator="\n")
    w.writeheader()
    for g in report["exact_groups"] + report["similar_groups"]:
        base = {"group_id": g["group_id"], "match_class": g["match_class"], "confidence": g["confidence"],
                "media_type": g["media_type"]}
        w.writerow({**base, "role": "original", "path": g["original"]["path"], "size": g["original"]["size"],
                    "sha256": g["original"]["sha256"] or "", "destination": "", "status": "retained",
                    "reason": g["original"]["selection_reason"], "tx_id": "", "timestamp": report["finished"]})
        for d in g["duplicates"]:
            w.writerow({**base, "role": "duplicate", "path": d["path"], "size": d["size"],
                        "sha256": d["sha256"] or "", "destination": d["destination"] or "", "status": d["status"],
                        "reason": d["reason"], "tx_id": d["tx_id"], "timestamp": d["timestamp"]})
    return buf.getvalue()


def report_text(report: Dict[str, Any], max_groups: int = 50, max_issues: int = 20) -> str:
    s = report["summary"]
    lines = [
        f"Duplicate Finder report  scan={report['scan_id']}  action={report['action']}  mode={report['mode']}",
        f"Roots: {', '.join(report['roots'])}",
        f"Destination: {report['destination']}",
        "",
        f"Files scanned:                   {s['files_scanned']}",
        f"Candidate files (same size):     {s['candidate_files']}",
        f"Verified exact duplicate groups: {s['exact_groups']}",
        f"Exact duplicate copies:          {s['exact_duplicate_copies']} "
        f"({human_bytes(s['exact_reclaimable_bytes'])} eligible for relocation)",
        f"Probable media duplicate groups: {s['probable_media_groups']}  (manual approval required)",
        f"Similar media needing review:    {s['review_media_groups']}  (manual approval required)",
    ]
    ms = s["move_status"]
    if ms:
        lines.append("Relocation: " + ", ".join(f"{k}={v}" for k, v in sorted(ms.items())))
        lines.append(f"Moved successfully (verified):   {ms.get('moved', 0)} ({human_bytes(s['moved_bytes'])})")
    if report["cancelled"]:
        lines.append("!! Run was cancelled; results are partial.")
    for w in report["warnings"]:
        lines.append(f"Warning: {w}")
    for name, st in report["detectors"].items():
        lines.append(f"Detector {name}: {st}")
    if s["issues"]:
        lines.append("Issues: " + ", ".join(f"{k}={v}" for k, v in sorted(s["issues"].items())))

    def section(title: str, groups: List[Dict[str, Any]]) -> None:
        if not groups:
            return
        lines.extend(["", title, "-" * len(title)])
        for g in groups[:max_groups]:
            lines.append(f"[{g['group_id']}] {g['match_class']} conf={g['confidence']} {g['media_type']} "
                         f"{human_bytes(g['size'])}" + (f" sha256={g['sha256'][:16]}..." if g["sha256"] else ""))
            lines.append(f"   KEEP  {g['original']['path']}   ({g['original']['selection_reason']})")
            for d in g["duplicates"]:
                arrow = f" -> {d['destination']}" if d["destination"] else ""
                note = f"  [{d['status']}{': ' + d['reason'] if d['reason'] else ''}]"
                lines.append(f"   MOVE  {d['path']}{arrow}{note}")
        if len(groups) > max_groups:
            lines.append(f"   ... {len(groups) - max_groups} more groups in the JSON/CSV report")

    section("Exact binary duplicates", report["exact_groups"])
    section("Similar media (never moved without explicit approval)", report["similar_groups"])
    noisy = {"unknown_type", "hard_link_alias", "symlink_skipped"}
    important = [i for i in report["issues"] if i["kind"] not in noisy]
    if important:
        lines.extend(["", "Problems", "--------"])
        for i in important[:max_issues]:
            lines.append(f"   {i['kind']}: {i['path']}: {i['message']}")
        if len(important) > max_issues:
            lines.append(f"   ... {len(important) - max_issues} more in the JSON report")
    return "\n".join(lines) + "\n"


def write_reports(report: Dict[str, Any], directory: Path, formats: List[str]) -> Dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    out: Dict[str, Path] = {}
    stem = f"report-{report['scan_id']}"
    for fmt in formats:
        path = directory / f"{stem}.{ 'txt' if fmt == 'text' else fmt}"
        if fmt == "json":
            data = json.dumps(report, indent=2, ensure_ascii=False, default=str)
        elif fmt == "csv":
            data = report_csv(report)
        else:
            data = report_text(report, max_groups=10**9, max_issues=10**9)
        # Reports are new files named by unique scan id; never overwrite.
        with open(path, "x", encoding="utf-8", newline="") as fh:
            fh.write(data)
        out[fmt] = path
    return out


def manifest_rows(entries: List[Any], redact: bool = False) -> List[Dict[str, Any]]:
    fmt = PathFormatter(redact)
    rows = []
    for e in entries:
        d = asdict(e)
        for k in ("original_path", "retained_original", "destination", "restored_to"):
            d[k] = fmt(d[k])
        rows.append(d)
    return rows


def manifest_csv(rows: List[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    fields = ["tx_id", "scan_id", "group_id", "match_class", "original_path", "retained_original", "destination",
              "sha256", "size", "timestamp", "restored", "restored_to"]
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k) for k in fields})
    return buf.getvalue()


__all__ = ["build_report", "report_csv", "report_text", "write_reports", "manifest_rows", "manifest_csv",
           "human_bytes", "now_iso"]
