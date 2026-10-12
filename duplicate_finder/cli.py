"""Command-line interface.

    python -m duplicate_finder scan PATH [PATH ...] [options]
    python -m duplicate_finder recover [--rollback]
    python -m duplicate_finder restore [--scan-id ID] [--tx TX] [--restore-to DIR] [--dry-run]
    python -m duplicate_finder manifest [--format csv|json] [--output FILE]
    python -m duplicate_finder cache stats|clear
    python -m duplicate_finder types

Exit codes: 0 ok, 1 completed with failures, 2 usage/configuration error,
3 refused for safety, 130 cancelled.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import __version__
from .config import ACTIONS, LAYOUTS, MODES, Config, apply_overrides, load_config_file
from .database import Database
from .errors import CancelledError, ConfigError, DuplicateFinderError, SafetyViolation
from .models import DuplicateGroup, MatchClass, MoveStatus, PlannedMove
from .reporting import human_bytes, manifest_csv, manifest_rows, report_text, build_report
from .runtime import CancelToken, Progress
from .transaction_log import Journal

EXIT_OK, EXIT_FAILURES, EXIT_USAGE, EXIT_SAFETY, EXIT_CANCELLED = 0, 1, 2, 3, 130

InputFn = Callable[[str], str]


def _size(text: str) -> int:
    t = text.strip().upper()
    mult = 1
    for suffix, m in (("KB", 1024), ("MB", 1024 ** 2), ("GB", 1024 ** 3), ("K", 1024), ("M", 1024 ** 2),
                      ("G", 1024 ** 3), ("B", 1)):
        if t.endswith(suffix):
            t, mult = t[: -len(suffix)], m
            break
    try:
        return int(float(t) * mult)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid size: {text}") from None


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--config", type=Path, help="TOML or JSON configuration file")
    p.add_argument("--state-dir", type=Path, help="directory for database, journal and reports")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose logging to stderr")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="duplicate_finder",
                                     description="Find duplicate media files by content and relocate surplus "
                                                 "copies safely. Never deletes a retained original.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan folders for duplicates (dry run by default)")
    s.add_argument("roots", nargs="+", type=Path, help="folders to scan (only these are ever touched)")
    _common(s)
    s.add_argument("--mode", choices=MODES, help="exact (default), similarity, or all")
    act = s.add_mutually_exclusive_group()
    act.add_argument("--dry-run", dest="action", action="store_const", const="dry-run",
                     help="show what would happen; change nothing (default)")
    act.add_argument("--report-only", dest="action", action="store_const", const="report",
                     help="write reports only; change nothing")
    act.add_argument("--interactive", dest="action", action="store_const", const="interactive",
                     help="review and approve each move")
    act.add_argument("--auto", dest="action", action="store_const", const="auto",
                     help="move verified exact duplicates automatically")
    act.add_argument("--action", dest="action", choices=ACTIONS)
    s.add_argument("--destination", type=Path, help="Duplicates folder (default: <parent of first root>/Duplicates)")
    s.add_argument("--layout", choices=LAYOUTS, help="destination layout (default: category)")
    s.add_argument("--verify", choices=("sha256", "bytes"), help="'bytes' adds full byte-by-byte comparison")
    s.add_argument("--workers", type=int, help="concurrent I/O workers (default 4)")
    s.add_argument("--chunk-size", type=_size, help="read chunk size, e.g. 1M (default 1M)")
    s.add_argument("--no-cache", dest="use_cache", action="store_false", default=None,
                   help="do not use cached hashes")
    s.add_argument("--exclude-dir", action="append", default=None, metavar="PATTERN",
                   help="directory name pattern to skip (repeatable, added to defaults)")
    s.add_argument("--exclude-file", action="append", default=None, metavar="PATTERN",
                   help="file name pattern to skip (repeatable, added to defaults)")
    s.add_argument("--min-size", type=_size)
    s.add_argument("--max-size", type=_size)
    s.add_argument("--types", help="comma list of image,video,audio,other (default: all)")
    s.add_argument("--follow-symlinks", action="store_true", default=None,
                   help="follow symbolic links whose targets are inside the scan roots")
    s.add_argument("--hardlinks-as-duplicates", action="store_true", default=None,
                   help="treat hard links to one file as separate copies")
    s.add_argument("--keep", help="comma list of rules choosing the copy to keep, e.g. oldest,shortest-path")
    s.add_argument("--prefer", action="append", type=Path, default=None, metavar="PATH",
                   help="prefer keeping copies under this folder (repeatable)")
    s.add_argument("--stability-seconds", type=float, help="skip files modified in the last N seconds")
    s.add_argument("--validate-media", action="store_true", default=None, help="decode files to detect corruption")
    s.add_argument("--report", action="append", choices=("json", "csv", "text", "all", "none"), default=None,
                   help="report format(s) to write (default: all)")
    s.add_argument("--report-dir", type=Path)
    s.add_argument("--redact-paths", action="store_true", default=None, help="replace home folder with ~ in reports")
    s.add_argument("--plugin", action="append", default=None, metavar="MODULE", help="handler plugin module")
    s.add_argument("--review-required", action="store_true",
                   help="(always on) similarity matches are never moved without approval")
    s.add_argument("-y", "--yes", action="store_true", help="skip the final confirmation in interactive mode")
    s.add_argument("--max-print", type=int, default=50, help="groups to print on screen")

    r = sub.add_parser("recover", help="reconcile interrupted operations from the journal")
    _common(r)
    r.add_argument("--rollback", action="store_true", help="keep sources in place instead of resuming moves")

    rs = sub.add_parser("restore", help="move relocated duplicates back to their original paths")
    _common(rs)
    rs.add_argument("--scan-id", help="restore only moves from this scan")
    rs.add_argument("--tx", action="append", help="restore only this transaction id (repeatable)")
    rs.add_argument("--restore-to", type=Path, help="alternative folder used when the original path is occupied")
    rs.add_argument("--dry-run", action="store_true", help="show what would be restored")
    rs.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")

    m = sub.add_parser("manifest", help="export the relocation manifest")
    _common(m)
    m.add_argument("--format", choices=("csv", "json"), default="csv")
    m.add_argument("--output", type=Path, help="write to a new file instead of stdout")
    m.add_argument("--redact-paths", action="store_true")

    c = sub.add_parser("cache", help="hash cache maintenance")
    _common(c)
    c.add_argument("op", choices=("stats", "clear"))

    t = sub.add_parser("types", help="list supported formats and optional capabilities")
    _common(t)
    return parser


# ---------------------------------------------------------------------- config

def make_config(args: argparse.Namespace) -> Config:
    cfg = Config()
    if getattr(args, "config", None):
        apply_overrides(cfg, load_config_file(args.config))
    if getattr(args, "state_dir", None):
        cfg.state_dir = args.state_dir
    if args.command != "scan":
        return cfg
    ov: Dict[str, Any] = {
        "roots": args.roots, "destination": args.destination, "mode": args.mode, "action": args.action,
        "layout": args.layout, "verify": args.verify, "workers": args.workers, "chunk_size": args.chunk_size,
        "use_cache": args.use_cache, "min_size": args.min_size, "max_size": args.max_size,
        "stability_seconds": args.stability_seconds, "validate_media": args.validate_media,
        "report_dir": args.report_dir, "redact_paths": args.redact_paths,
        "hardlinks_as_duplicates": args.hardlinks_as_duplicates, "prefer_paths": args.prefer,
    }
    apply_overrides(cfg, ov)
    if args.exclude_dir:
        cfg.exclude_dirs = cfg.exclude_dirs + args.exclude_dir
    if args.exclude_file:
        cfg.exclude_files = cfg.exclude_files + args.exclude_file
    if args.types:
        cfg.categories = [t.strip() for t in args.types.split(",") if t.strip()]
    if args.follow_symlinks:
        cfg.symlink_policy = "follow-within-roots"
    if args.keep:
        cfg.keep = [k.strip() for k in args.keep.split(",") if k.strip()]
    if args.plugin:
        cfg.plugins = cfg.plugins + args.plugin
    if args.report:
        if "none" in args.report:
            cfg.report_formats = []
        elif "all" in args.report:
            cfg.report_formats = ["json", "csv", "text"]
        else:
            cfg.report_formats = list(dict.fromkeys(args.report))
    if args.quiet:
        cfg.progress = False
    cfg.assume_yes = bool(args.yes)
    cfg.validate()
    return cfg


# ---------------------------------------------------------------------- interactive approval

def interactive_approver(input_fn: InputFn = input, out=None, assume_yes: bool = False):
    out = out or sys.stdout

    def say(msg: str = "") -> None:
        out.write(msg + "\n")
        out.flush()

    def approve(moves: List[PlannedMove], groups: List[DuplicateGroup]) -> bool:
        by_group: Dict[str, List[PlannedMove]] = {}
        for mv in moves:
            by_group.setdefault(mv.group_id, []).append(mv)
        approve_all_exact = False
        for g in groups:
            gm = [m for m in by_group.get(g.group_id, []) if m.status is MoveStatus.PLANNED]
            if not gm:
                continue
            exact = g.match_class is MatchClass.EXACT
            say("")
            say(f"[{g.group_id}] {g.match_class.value}  confidence={g.confidence}  {human_bytes(g.original.size)}")
            say(f"  KEEP   {g.original.path}  ({g.selection_reason})")
            if not exact:
                for p in g.evidence.get("pairs", [])[:5]:
                    detail = {k: v for k, v in p.items() if k not in ("a", "b")}
                    say(f"  evidence: {detail}")
                say("  NOTE: these files are NOT byte-identical. Approve only if you are sure.")
            for mv in gm:
                if exact and approve_all_exact:
                    mv.status = MoveStatus.APPROVED
                    continue
                say(f"  MOVE?  {mv.source.path}\n     -> {mv.destination}")
                if exact:
                    ans = input_fn("  [y]es / [n]o / [a]ll remaining exact / [s]kip group / [q]uit review: ").strip().lower()
                else:
                    ans = input_fn("  type 'yes' to move this similar file, anything else to skip: ").strip().lower()
                    ans = "y" if ans == "yes" else "n"
                if ans in ("q", "quit"):
                    return _confirm(moves, input_fn, say, assume_yes)
                if ans in ("s", "skip"):
                    for m in gm:
                        if m.status is MoveStatus.PLANNED:
                            m.status, m.reason = MoveStatus.REJECTED, "rejected by user"
                    break
                if ans in ("a", "all") and exact:
                    approve_all_exact = True
                    mv.status = MoveStatus.APPROVED
                elif ans in ("y", "yes"):
                    mv.status = MoveStatus.APPROVED
                else:
                    mv.status, mv.reason = MoveStatus.REJECTED, "rejected by user"
        return _confirm(moves, input_fn, say, assume_yes)

    return approve


def _confirm(moves: List[PlannedMove], input_fn: InputFn, say, assume_yes: bool) -> bool:
    approved = [m for m in moves if m.status is MoveStatus.APPROVED]
    for m in moves:
        if m.status is MoveStatus.PLANNED:
            m.status, m.reason = MoveStatus.REJECTED, "not reviewed"
    if not approved:
        say("No moves approved.")
        return False
    total = sum(m.source.size for m in approved)
    say(f"\n{len(approved)} file(s), {human_bytes(total)} approved for relocation.")
    if assume_yes:
        return True
    return input_fn("Execute these moves now? [y/N]: ").strip().lower() in ("y", "yes")


# ---------------------------------------------------------------------- commands

def _install_sigint(cancel: CancelToken) -> Optional[Any]:
    if threading.current_thread() is not threading.main_thread():
        return None

    def handler(signum, frame):  # noqa: ARG001
        if cancel.cancelled:
            raise KeyboardInterrupt
        cancel.cancel()
        sys.stderr.write("\nCancelling... finishing the current file safely (Ctrl+C again to abort now)\n")

    return signal.signal(signal.SIGINT, handler)


def cmd_scan(args: argparse.Namespace, input_fn: InputFn, out) -> int:
    from .pipeline import Engine

    cfg = make_config(args)
    cancel = CancelToken()
    previous = _install_sigint(cancel)
    approver = interactive_approver(input_fn, out, cfg.assume_yes) if cfg.action == "interactive" else None
    if cfg.action == "auto" and not cfg.assume_yes and cfg.progress:
        out.write("Automatic mode: verified exact duplicates will be moved to "
                  f"{cfg.effective_destination()}\n")
    try:
        engine = Engine(cfg, cancel=cancel, progress=Progress(cfg.progress))
        result = engine.run(approver)
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)
    report = build_report(result, cfg.redact_paths)
    out.write(report_text(report, max_groups=args.max_print))
    if cfg.action in ("dry-run", "report"):
        out.write("\nNo files were changed" + (" (dry run)." if cfg.action == "dry-run" else ".") + "\n")
    for fmt, p in result.report_paths.items():
        out.write(f"Report ({fmt}): {p}\n")
    if result.cancelled:
        return EXIT_CANCELLED
    return EXIT_FAILURES if result.failures else EXIT_OK


def cmd_recover(args: argparse.Namespace, out) -> int:
    from .recovery import recover

    cfg = make_config(args)
    journal = Journal(cfg.journal_path)
    with Database(cfg.db_path) as db:
        rep = recover(journal, db, rollback=args.rollback, chunk_size=cfg.chunk_size)
    if not rep.items:
        out.write("No interrupted operations found. Nothing to do.\n")
        return EXIT_OK
    for it in rep.items:
        flag = "!! " if it.critical else ""
        out.write(f"{flag}{it.tx_id[:12]} {it.kind}: {it.source} -> {it.destination or '-'}: "
                  f"{it.outcome} ({it.detail})\n")
    out.write(f"{len(rep.items)} operation(s) reconciled.\n")
    return EXIT_FAILURES if rep.critical else EXIT_OK


def cmd_restore(args: argparse.Namespace, input_fn: InputFn, out) -> int:
    from .recovery import manifest, restore

    cfg = make_config(args)
    journal = Journal(cfg.journal_path)
    pending = journal.incomplete()
    if pending and not args.dry_run:
        out.write(f"{len(pending)} interrupted operation(s) found; run 'recover' first.\n")
        return EXIT_SAFETY
    entries = [e for e in manifest(journal) if not e.restored
               and (not args.scan_id or e.scan_id == args.scan_id) and (not args.tx or e.tx_id in args.tx)]
    if not entries:
        out.write("Nothing to restore.\n")
        return EXIT_OK

    def ask(target: Path, stored: Path) -> Optional[Path]:
        if not sys.stdin.isatty() or args.yes:
            return None
        ans = input_fn(f"{target} already exists. Folder to restore {stored.name} into (empty = skip): ").strip()
        return Path(ans) if ans else None

    if not args.dry_run and not args.yes:
        ans = input_fn(f"Restore {len(entries)} file(s) to their original locations? [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            out.write("Cancelled.\n")
            return EXIT_OK
    with Database(cfg.db_path) as db:
        items = restore(journal, db, scan_id=args.scan_id, tx_ids=args.tx, restore_to=args.restore_to,
                        ask_new_destination=ask, chunk_size=cfg.chunk_size, dry_run=args.dry_run)
    for it in items:
        out.write(f"{it.status:9} {it.from_path} -> {it.to_path or '-'}  {it.detail}\n")
    bad = [i for i in items if i.status in ("failed", "conflict")]
    return EXIT_FAILURES if bad else EXIT_OK


def cmd_manifest(args: argparse.Namespace, out) -> int:
    from .recovery import manifest

    cfg = make_config(args)
    rows = manifest_rows(manifest(Journal(cfg.journal_path)), args.redact_paths)
    text = json.dumps(rows, indent=2, ensure_ascii=False) if args.format == "json" else manifest_csv(rows)
    if args.output:
        with open(args.output, "x", encoding="utf-8", newline="") as fh:  # never overwrite
            fh.write(text)
        out.write(f"Manifest written to {args.output} ({len(rows)} entries)\n")
    else:
        out.write(text)
    return EXIT_OK


def cmd_cache(args: argparse.Namespace, out) -> int:
    cfg = make_config(args)
    with Database(cfg.db_path) as db:
        if args.op == "clear":
            n = db.clear_cache()
            out.write(f"Cleared {n} cached hash entries (no user files touched).\n")
        else:
            out.write(json.dumps(db.cache_stats(), indent=2) + "\n")
    return EXIT_OK


def cmd_types(args: argparse.Namespace, out) -> int:
    from . import media_probe
    from .detectors import detector_classes
    from .file_types import default_registry

    cfg = make_config(args)
    for h in default_registry().handlers:
        out.write(f"[{h.name}]\n")
        for fmt, spec in h.formats.items():
            out.write(f"  {fmt:8} {spec.category.value:6} {' '.join(spec.extensions)}\n")
    out.write("\nOptional capabilities:\n")
    for mod in ("PIL", "imagehash", "mutagen", "pillow_heif"):
        try:
            __import__(mod)
            state = "available"
        except ImportError:
            state = "not installed"
        out.write(f"  python module {mod:12} {state}\n")
    for tool in ("ffprobe", "ffmpeg", "fpcalc"):
        out.write(f"  program {tool:18} {media_probe.which(tool) or 'not found'}\n")
    for cls in detector_classes():
        ok, why = cls(cfg).available()
        out.write(f"  similarity detector {cls.name:6} {'available' if ok else 'unavailable: ' + why}\n")
    out.write(f"\nState directory: {cfg.state_dir}\n")
    return EXIT_OK


def _setup_logging(args: argparse.Namespace) -> None:
    level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def main(argv: Optional[Sequence[str]] = None, input_fn: InputFn = input, out=None) -> int:
    out = out or sys.stdout
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args)
    try:
        if args.command == "scan":
            return cmd_scan(args, input_fn, out)
        if args.command == "recover":
            return cmd_recover(args, out)
        if args.command == "restore":
            return cmd_restore(args, input_fn, out)
        if args.command == "manifest":
            return cmd_manifest(args, out)
        if args.command == "cache":
            return cmd_cache(args, out)
        if args.command == "types":
            return cmd_types(args, out)
    except ConfigError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_USAGE
    except SafetyViolation as exc:
        sys.stderr.write(f"refused: {exc}\n")
        return EXIT_SAFETY
    except (CancelledError, KeyboardInterrupt):
        sys.stderr.write("cancelled\n")
        return EXIT_CANCELLED
    except DuplicateFinderError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_FAILURES
    parser.error("unknown command")
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
