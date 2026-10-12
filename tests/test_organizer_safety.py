"""Relocation safety: spec §5, §13 cases 12-14, 16, 21 and the acceptance criteria."""

from __future__ import annotations

import errno
import os
import unittest
from pathlib import Path
from unittest import mock

from duplicate_finder import organizer as organizer_mod
from duplicate_finder.config import Config
from duplicate_finder.errors import ConfigError, SafetyViolation
from duplicate_finder.models import MatchClass, MoveStatus
from duplicate_finder.organizer import candidate_names
from duplicate_finder.pipeline import Engine
from duplicate_finder.runtime import CancelToken, Progress
from duplicate_finder.transaction_log import Journal

from tests.helpers import IS_WINDOWS, TempTreeCase


class DryRunTests(TempTreeCase):
    def test_dry_run_changes_nothing(self):
        for i in range(3):
            self.write(f"d{i}/same.jpg", b"\xff\xd8\xff" + b"P" * 2000)
        self.write("other.txt", b"unique")
        before = self.snapshot()
        r = self.run_engine(action="dry-run")
        self.assertEqual(len(r.exact_groups), 1)
        self.assertTrue(all(m.status is MoveStatus.PLANNED for m in r.moves))
        self.assertTrue(all(m.destination is not None for m in r.moves))
        self.assertEqual(self.snapshot(), before, "dry run modified the filesystem")
        self.assertFalse(self.dest.exists(), "dry run created the Duplicates folder")

    def test_report_only_changes_nothing(self):
        self.write("a.bin", b"1" * 10)
        self.write("b.bin", b"1" * 10)
        before = self.snapshot()
        r = self.run_engine(action="report", report_formats=["json", "csv", "text"])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(set(r.report_paths), {"json", "csv", "text"})
        for p in r.report_paths.values():
            self.assertTrue(p.exists())


class AutoModeTests(TempTreeCase):
    def test_moves_duplicates_and_keeps_original(self):
        orig = self.write("keep/photo.jpg", b"\xff\xd8\xff" + b"Q" * 3000)
        os.utime(orig, (1_000_000_000, 1_000_000_000))  # oldest -> retained
        d1 = self.write("x/photo.jpg", b"\xff\xd8\xff" + b"Q" * 3000)
        d2 = self.write("y/copy.jpg", b"\xff\xd8\xff" + b"Q" * 3000)
        content_before = self.all_content_hashes()
        r = self.run_engine(action="auto")
        self.assertEqual([m.status for m in r.moves], [MoveStatus.MOVED, MoveStatus.MOVED])
        self.assertTrue(orig.exists(), "retained original was removed")
        self.assertFalse(d1.exists())
        self.assertFalse(d2.exists())
        self.assertTrue((self.dest / "Images" / "photo.jpg").exists())
        self.assertTrue((self.dest / "Images" / "copy.jpg").exists())
        self.assertEqual(self.all_content_hashes(), content_before, "content was lost or altered")

    def test_auto_never_moves_similar_media(self):
        from duplicate_finder.detectors.base import SimilarityMatch
        a = self.write("a.bin", b"A" * 100)
        b = self.write("b.bin", b"B" * 100)
        fake = mock.Mock()
        fake.return_value = []

        def fake_similarity(self_engine, records, exact, roots, result):
            from duplicate_finder.detectors import build_groups
            ra = next(r for r in records if r.path == a)
            rb = next(r for r in records if r.path == b)
            return build_groups([SimilarityMatch(ra, rb, MatchClass.PROBABLE, 0.99, {"method": "fake"})],
                                self_engine.cfg, roots)

        with mock.patch.object(Engine, "_similarity", fake_similarity):
            r = self.run_engine(action="auto", mode="all")
        self.assertEqual(len(r.similar_groups), 1)
        self.assertTrue(a.exists() and b.exists())
        self.assertTrue(all(m.status is MoveStatus.PLANNED for m in r.moves))

    def test_similarity_match_cannot_be_exact(self):
        from duplicate_finder.detectors.base import SimilarityMatch
        with self.assertRaises(ValueError):
            SimilarityMatch(None, None, MatchClass.EXACT, 1.0)  # type: ignore[arg-type]

    def test_unicode_and_spaces_in_paths(self):  # case 19
        name = "Ünïcødé фото 写真 (copy).jpg"
        self.write("dir with spaces/" + name, b"\xff\xd8\xff" + b"u" * 50)
        self.write("другая папка/" + name, b"\xff\xd8\xff" + b"u" * 50)
        r = self.run_engine(action="auto")
        self.assertEqual(r.moves[0].status, MoveStatus.MOVED)
        self.assertTrue((self.dest / "Images" / name).exists())

    def test_mirror_and_flat_layouts(self):
        self.write("a/b/f.bin", b"m" * 10)
        self.write("c/f.bin", b"m" * 10)
        r = self.run_engine(action="auto", layout="mirror")
        dest = r.moves[0].destination
        self.assertTrue(str(dest).startswith(str(self.dest / "Other" / "root")))
        self.assertTrue(dest.exists())


class CollisionTests(TempTreeCase):
    def test_candidate_names(self):
        names = candidate_names("photo.jpg")
        self.assertEqual([next(names) for _ in range(3)],
                         ["photo.jpg", "photo__duplicate_001.jpg", "photo__duplicate_002.jpg"])

    def test_existing_destination_files_never_overwritten(self):  # cases 12, 13
        existing = self.write("Images/photo.jpg", b"PRE-EXISTING", base=self.dest)
        existing2 = self.write("Images/photo__duplicate_001.jpg", b"PRE-EXISTING-2", base=self.dest)
        self.write("a/photo.jpg", b"\xff\xd8\xff" + b"c" * 100)
        self.write("b/photo.jpg", b"\xff\xd8\xff" + b"c" * 100)
        self.write("c/photo.jpg", b"\xff\xd8\xff" + b"c" * 100)
        r = self.run_engine(action="auto")
        self.assertEqual(existing.read_bytes(), b"PRE-EXISTING")
        self.assertEqual(existing2.read_bytes(), b"PRE-EXISTING-2")
        dests = sorted(m.destination.name for m in r.moves)
        self.assertEqual(dests, ["photo__duplicate_002.jpg", "photo__duplicate_003.jpg"])
        self.assertTrue(all(m.status is MoveStatus.MOVED for m in r.moves))

    def test_collision_appearing_after_planning(self):
        # Another process creates the planned name between plan and move.
        self.write("a/p.jpg", b"\xff\xd8\xff" + b"z" * 10)
        self.write("b/p.jpg", b"\xff\xd8\xff" + b"z" * 10)
        original_execute = organizer_mod.Organizer._execute_one

        def racing(self_org, mv):
            mv.destination.parent.mkdir(parents=True, exist_ok=True)
            mv.destination.write_bytes(b"RACE WINNER")
            return original_execute(self_org, mv)

        with mock.patch.object(organizer_mod.Organizer, "_execute_one", racing):
            r = self.run_engine(action="auto")
        self.assertEqual((self.dest / "Images" / "p.jpg").read_bytes(), b"RACE WINNER")
        self.assertEqual(r.moves[0].destination.name, "p__duplicate_001.jpg")

    def test_case_insensitive_collision_reserved(self):
        # On case-insensitive filesystems "PHOTO.JPG" collides with "photo.jpg";
        # exclusive creation handles that at the OS level. Planning is conservative too.
        self.write("a/photo.jpg", b"\xff\xd8\xff" + b"k" * 10)
        self.write("b/PHOTO.JPG", b"\xff\xd8\xff" + b"k" * 10)
        self.write("c/Photo.jpg", b"\xff\xd8\xff" + b"k" * 10)
        r = self.run_engine(action="dry-run")
        planned = [str(m.destination.name).lower() for m in r.moves]
        self.assertEqual(len(set(planned)), len(planned), "plan must not reuse a name that differs only by case")


class RevalidationTests(TempTreeCase):
    def _approve_after(self, mutate):
        def approver(moves, groups):
            mutate()
            for m in moves:
                m.status = MoveStatus.APPROVED
            return True
        return approver

    def test_source_modified_between_scan_and_move(self):  # case 14
        a = self.write("a.bin", b"S" * 1000)
        b = self.write("b.bin", b"S" * 1000)
        os.utime(a, (1, 1))

        def mutate():
            b.write_bytes(b"T" * 1000)
        r = self.run_engine(action="interactive", approver=self._approve_after(mutate))
        self.assertEqual(r.moves[0].status, MoveStatus.SKIPPED)
        self.assertIn("changed", r.moves[0].reason)
        self.assertEqual(b.read_bytes(), b"T" * 1000)
        self.assertTrue(a.exists())

    def test_original_modified_before_move(self):
        a = self.write("a.bin", b"S" * 1000)
        b = self.write("b.bin", b"S" * 1000)
        os.utime(a, (1, 1))

        def mutate():
            a.write_bytes(b"X" * 1000)
        r = self.run_engine(action="interactive", approver=self._approve_after(mutate))
        self.assertEqual(r.moves[0].status, MoveStatus.SKIPPED)
        self.assertTrue(b.exists(), "duplicate must stay when the original no longer matches")

    def test_original_deleted_before_move(self):
        a = self.write("a.bin", b"S" * 1000)
        b = self.write("b.bin", b"S" * 1000)
        os.utime(a, (1, 1))
        r = self.run_engine(action="interactive", approver=self._approve_after(
            lambda: os.replace(a, self.tmp / "elsewhere.bin")))
        self.assertEqual(r.moves[0].status, MoveStatus.SKIPPED)
        self.assertTrue(b.exists(), "last remaining copy must never be moved away")

    def test_source_replaced_by_symlink(self):
        if IS_WINDOWS:
            self.skipTest("symlink creation needs privileges on Windows")
        a = self.write("a.bin", b"S" * 1000)
        b = self.write("b.bin", b"S" * 1000)
        os.utime(a, (1, 1))

        def mutate():
            os.replace(b, self.tmp / "moved_away.bin")
            os.symlink(self.tmp / "moved_away.bin", b)
        r = self.run_engine(action="interactive", approver=self._approve_after(mutate))
        self.assertEqual(r.moves[0].status, MoveStatus.SKIPPED)
        self.assertTrue(os.path.islink(b))


class CrossFilesystemTests(TempTreeCase):
    def _run_with_link(self, link_func, **kw):
        orig_init = organizer_mod.Organizer.__init__

        def init(self_org, *a, **k):
            orig_init(self_org, *a, **k)
            self_org._link_func = link_func
        with mock.patch.object(organizer_mod.Organizer, "__init__", init):
            return self.run_engine(action="auto", **kw)

    def test_exdev_falls_back_to_verified_copy(self):  # case 16
        self.write("a/v.mp4", b"\x00\x00\x00\x18ftypisom" + b"v" * 200000)
        b = self.write("b/v.mp4", b"\x00\x00\x00\x18ftypisom" + b"v" * 200000)
        os.utime(self.root / "a/v.mp4", (1, 1))

        def exdev(src, dst):
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        r = self._run_with_link(exdev)
        mv = r.moves[0]
        self.assertEqual(mv.status, MoveStatus.MOVED)
        self.assertIn("copy", mv.reason)
        self.assertFalse(b.exists())
        self.assertEqual(mv.destination.read_bytes(), b"\x00\x00\x00\x18ftypisom" + b"v" * 200000)
        self.assertEqual(mv.destination.parent.name, "Videos")

    def test_copy_failure_retains_source(self):
        a = self.write("a.bin", b"F" * 50000)
        b = self.write("b.bin", b"F" * 50000)
        os.utime(a, (1, 1))

        def exdev(src, dst):
            raise OSError(errno.EXDEV, "cross-device")
        real_write = os.write
        calls = {"n": 0}

        def failing_write(fd, data):
            calls["n"] += 1
            raise OSError(errno.ENOSPC, "No space left on device")
        with mock.patch.object(organizer_mod, "_os_write", failing_write):
            r = self._run_with_link(exdev)
        mv = r.moves[0]
        self.assertEqual(mv.status, MoveStatus.FAILED)
        self.assertIn("source retained", mv.reason)
        self.assertTrue(a.exists() and b.exists())
        self.assertEqual(b.read_bytes(), b"F" * 50000)
        del real_write

    def test_corrupted_copy_detected(self):
        a = self.write("a.bin", b"C" * 50000)
        b = self.write("b.bin", b"C" * 50000)
        os.utime(a, (1, 1))

        def exdev(src, dst):
            raise OSError(errno.EXDEV, "cross-device")
        real_sha = organizer_mod.sha256_file

        def bad_sha(path, *args, **kw):
            digest, fp = real_sha(path, *args, **kw)
            if "Duplicates" in str(path):
                return "0" * 64, fp  # destination reads back wrong
            return digest, fp
        with mock.patch.object(organizer_mod, "sha256_file", bad_sha):
            r = self._run_with_link(exdev)
        self.assertEqual(r.moves[0].status, MoveStatus.FAILED)
        self.assertTrue(b.exists(), "source must be kept when the copy does not verify")

    def test_source_removal_failure_keeps_both(self):
        a = self.write("a.bin", b"R" * 100)
        b = self.write("b.bin", b"R" * 100)
        os.utime(a, (1, 1))
        real_unlink = os.unlink

        def deny(path, *a2, **k):
            if Path(path) == b:
                raise PermissionError(errno.EACCES, "file in use")
            return real_unlink(path, *a2, **k)
        with mock.patch.object(organizer_mod.os, "unlink", deny):
            r = self.run_engine(action="auto")
        mv = r.moves[0]
        self.assertEqual(mv.status, MoveStatus.INCOMPLETE)
        self.assertTrue(b.exists() and mv.destination.exists() and a.exists())
        self.assertNotEqual(mv.status, MoveStatus.MOVED, "must not report success for unverified move")


class CancellationTests(TempTreeCase):
    def test_cancel_during_scan(self):  # case 21 (scan)
        for i in range(30):
            self.write(f"d{i}/f.bin", b"x" * 10)
        tok = CancelToken()
        tok.cancel()
        before = self.snapshot()
        r = self.run_engine(action="auto", cancel=tok)
        self.assertTrue(r.cancelled)
        self.assertEqual(self.snapshot(), before)

    def test_cancel_during_relocation_finishes_current_file_only(self):  # case 21 (relocation)
        for i in range(5):
            self.write(f"d{i}/f.bin", b"same" * 10)
        tok = CancelToken()
        orig_exec = organizer_mod.Organizer._execute_one
        state = {"n": 0}

        def exec_then_cancel(self_org, mv):
            state["n"] += 1
            orig_exec(self_org, mv)
            tok.cancel()
        content_before = self.all_content_hashes()
        with mock.patch.object(organizer_mod.Organizer, "_execute_one", exec_then_cancel):
            r = self.run_engine(action="auto", cancel=tok)
        statuses = [m.status for m in r.moves]
        self.assertEqual(statuses.count(MoveStatus.MOVED), 1)
        self.assertEqual(statuses.count(MoveStatus.SKIPPED), 3)
        self.assertEqual(self.all_content_hashes(), content_before)
        self.assertEqual(Journal(self.state / "journal.jsonl").incomplete(), [])


class DestinationSafetyTests(TempTreeCase):
    def test_destination_inside_root_is_not_rescanned(self):
        inner = self.root / "Duplicates"
        self.write("a.bin", b"d" * 10)
        self.write("b.bin", b"d" * 10)
        r1 = self.run_engine(action="auto", destination=inner)
        self.assertEqual(r1.moves[0].status, MoveStatus.MOVED)
        r2 = self.run_engine(action="auto", destination=inner)
        self.assertEqual(r2.exact_groups, [], "files in Duplicates were rediscovered")

    def test_root_inside_destination_refused(self):
        with self.assertRaises(ConfigError):
            self.run_engine(destination=self.tmp)

    def test_planted_symlink_in_destination_refused(self):
        if IS_WINDOWS:
            self.skipTest("symlinks need privileges on Windows")
        outside = self.tmp / "outside"
        outside.mkdir()
        self.dest.mkdir()
        os.symlink(outside, self.dest / "Other")
        self.write("a.bin", b"e" * 10)
        b = self.write("b.bin", b"e" * 10)
        os.utime(self.root / "a.bin", (1, 1))
        r = self.run_engine(action="auto")
        self.assertEqual(r.moves[0].status, MoveStatus.SKIPPED)
        self.assertTrue(b.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_pending_journal_blocks_new_moves(self):
        j = Journal(self.state / "journal.jsonl")
        j.append("tx1", "intent", kind="move", source=str(self.root / "x"), sha256="0", size=1)
        self.write("a.bin", b"q")
        self.write("b.bin", b"q")
        with self.assertRaises(SafetyViolation):
            self.run_engine(action="auto")
        # dry-run is still allowed
        self.run_engine(action="dry-run")

    def test_hardlinks_not_moved_as_duplicates(self):  # case 17 (hard links)
        a = self.write("a.bin", b"h" * 100)
        try:
            os.link(a, self.root / "b.bin")
        except OSError:
            self.skipTest("hard links unsupported")
        r = self.run_engine(action="auto")
        self.assertEqual(r.exact_groups, [])
        self.assertTrue((self.root / "b.bin").exists())


class NoDeletionStaticTests(unittest.TestCase):
    """The only file-removal call in the package is the guarded final step of a verified move."""

    FORBIDDEN = ("os.remove(", "os.unlink(", "os.rmdir(", ".unlink(", ".rmdir(", "shutil.rmtree(",
                 "removedirs(", "send2trash", "shutil.move(", "os.replace(", "os.rename(")

    def test_single_removal_point(self):
        pkg = Path(__file__).resolve().parent.parent / "duplicate_finder"
        hits = []
        for py in pkg.rglob("*.py"):
            for lineno, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0]
                for f in self.FORBIDDEN:
                    if f in code:
                        hits.append((py.name, lineno, f, line.strip()))
        allowed = {("organizer.py", "os.unlink("), ("organizer.py", ".unlink("), ("database.py", "os.rename(")}
        unexpected = [h for h in hits if (h[0], h[2]) not in allowed]
        self.assertEqual(unexpected, [], f"unexpected file-removal/overwrite calls: {unexpected}")
        unlinks = [h for h in hits if h[2] == "os.unlink("]
        self.assertIn("_remove_source_after_verified_move", (pkg / "organizer.py").read_text(encoding="utf-8"))
        self.assertEqual(len(unlinks), 1, unlinks)
        # database.py's rename only moves its *own* corrupt state file aside
        for h in hits:
            if h[2] == "os.rename(":
                self.assertEqual(h[0], "database.py")


if __name__ == "__main__":
    unittest.main()
