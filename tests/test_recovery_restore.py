"""Journal, crash recovery and restore: spec §13 cases 15 and 22."""

from __future__ import annotations

import errno
import os
import unittest
from pathlib import Path
from unittest import mock

from duplicate_finder import organizer as organizer_mod
from duplicate_finder.database import Database
from duplicate_finder.models import MoveStatus
from duplicate_finder.recovery import manifest, recover, restore
from duplicate_finder.transaction_log import Journal

from tests.helpers import TempTreeCase


class Crash(BaseException):
    """Simulates the process dying (not caught by ordinary error handling)."""


class RecoveryTests(TempTreeCase):
    def setUp(self):
        super().setUp()
        self.a = self.write("a/song.mp3", b"ID3" + b"\x00" * 7 + b"music" * 4000)
        self.b = self.write("b/song.mp3", b"ID3" + b"\x00" * 7 + b"music" * 4000)
        os.utime(self.a, (1, 1))
        self.journal = Journal(self.state / "journal.jsonl")

    def _crash_at(self, target: str, exdev: bool = False):
        patches = [mock.patch.object(organizer_mod, target, side_effect=Crash())]
        if exdev:
            orig_init = organizer_mod.Organizer.__init__

            def init(self_org, *a, **k):
                orig_init(self_org, *a, **k)

                def no_link(s, d):
                    raise OSError(errno.EXDEV, "cross-device")
                self_org._link_func = no_link
            patches.append(mock.patch.object(organizer_mod.Organizer, "__init__", init))
        for p in patches:
            p.start()
        try:
            with self.assertRaises(Crash):
                self.run_engine(action="auto")
        finally:
            for p in patches:
                p.stop()
        self.journal.unlock()

    def test_crash_after_verified_copy_resume(self):  # case 15
        self._crash_at("_remove_source_after_verified_move")
        pending = self.journal.incomplete()
        self.assertEqual(len(pending), 1)
        self.assertTrue(self.b.exists(), "source must survive a crash before removal")
        rep = recover(self.journal, Database(self.state / "state.sqlite3"))
        self.assertEqual([i.outcome for i in rep.items], ["committed"])
        self.assertFalse(self.b.exists())
        self.assertTrue(self.a.exists())
        self.assertTrue((self.dest / "Audio" / "song.mp3").exists())
        self.assertEqual(self.journal.incomplete(), [])
        self.assertEqual(len(manifest(self.journal)), 1)

    def test_crash_after_verified_copy_rollback(self):
        self._crash_at("_remove_source_after_verified_move", exdev=True)
        rep = recover(self.journal, rollback=True)
        self.assertEqual(rep.items[0].outcome, "rolled_back")
        self.assertTrue(self.b.exists() and self.a.exists())
        self.assertTrue((self.dest / "Audio" / "song.mp3").exists(), "extra copy is kept, never deleted")

    def test_crash_during_copy_incomplete_destination(self):
        # Crash after the destination was reserved but before verification.
        self._crash_at("sha256_file", exdev=True)
        # sha256_file is first used for revalidation -> crash before intent: nothing journaled.
        self.assertEqual(self.journal.incomplete(), [])
        # Now simulate a torn copy explicitly.
        dest = self.dest / "Audio" / "song.mp3"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(b"ID3partial")
        tx = "deadbeef"
        self.journal.append(tx, "intent", kind="move", source=str(self.b), original=str(self.a),
                            sha256=self._sha(self.b), size=self.b.stat().st_size, dest_dir=str(dest.parent),
                            filename="song.mp3", match_class="exact_binary_duplicate",
                            original_sha256=self._sha(self.a))
        self.journal.append(tx, "dest_reserved", destination=str(dest), method="copy")
        self.journal.path.open("ab").write(b'{"tx":"deadbeef","event":"dest_ver')  # torn last line
        rep = recover(self.journal)
        self.assertEqual(rep.items[0].outcome, "rolled_back")
        self.assertIn("incomplete", rep.items[0].detail)
        self.assertTrue(self.b.exists())
        self.assertTrue(dest.exists(), "recovery never deletes, even an incomplete copy")

    def test_intent_without_destination(self):
        tx = "cafe"
        self.journal.append(tx, "intent", kind="move", source=str(self.b), original=str(self.a),
                            sha256=self._sha(self.b), size=self.b.stat().st_size,
                            dest_dir=str(self.dest / "Audio"), filename="song.mp3")
        rep = recover(self.journal)
        self.assertEqual(rep.items[0].outcome, "aborted")
        self.assertTrue(self.b.exists())

    def test_resume_refused_if_original_changed(self):
        self._crash_at("_remove_source_after_verified_move")
        self.a.write_bytes(b"edited original")
        rep = recover(self.journal)
        self.assertEqual(rep.items[0].outcome, "rolled_back")
        self.assertTrue(self.b.exists(), "duplicate must stay when the retained original changed")

    def test_source_gone_destination_verified(self):
        self._crash_at("_remove_source_after_verified_move")
        dest = self.dest / "Audio" / "song.mp3"
        # emulate: removal happened but the journal line was lost
        organizer_mod.os.unlink(self.b)
        rep = recover(self.journal)
        self.assertEqual(rep.items[0].outcome, "committed")
        self.assertTrue(dest.exists())

    @staticmethod
    def _sha(p: Path) -> str:
        import hashlib
        return hashlib.sha256(p.read_bytes()).hexdigest()


class RestoreTests(TempTreeCase):
    def setUp(self):
        super().setUp()
        self.a = self.write("x/pic.png", b"\x89PNG\r\n\x1a\n" + b"p" * 500)
        self.b = self.write("y/pic.png", b"\x89PNG\r\n\x1a\n" + b"p" * 500)
        os.utime(self.a, (1, 1))
        self.journal = Journal(self.state / "journal.jsonl")
        r = self.run_engine(action="auto")
        self.assertEqual(r.moves[0].status, MoveStatus.MOVED)
        self.stored = r.moves[0].destination

    def test_restore_roundtrip(self):
        items = restore(self.journal)
        self.assertEqual([i.status for i in items], ["restored"])
        self.assertTrue(self.b.exists())
        self.assertFalse(self.stored.exists())
        self.assertTrue(manifest(self.journal)[0].restored)
        self.assertEqual(restore(self.journal), [], "already restored items are not restored twice")

    def test_restore_conflict_keeps_both(self):  # case 22
        self.b.write_bytes(b"NEW FILE AT ORIGINAL PATH")
        items = restore(self.journal)
        self.assertEqual(items[0].status, "conflict")
        self.assertEqual(self.b.read_bytes(), b"NEW FILE AT ORIGINAL PATH")
        self.assertTrue(self.stored.exists())

    def test_restore_conflict_with_alternative_folder(self):
        self.b.write_bytes(b"occupant")
        alt = self.tmp / "restored"
        items = restore(self.journal, restore_to=alt)
        self.assertEqual(items[0].status, "restored")
        self.assertEqual(self.b.read_bytes(), b"occupant")
        restored = Path(items[0].to_path)
        self.assertTrue(str(restored).startswith(str(alt)))
        self.assertEqual(restored.read_bytes(), b"\x89PNG\r\n\x1a\n" + b"p" * 500)

    def test_restore_conflict_alternative_also_occupied(self):
        self.b.write_bytes(b"occupant")
        alt = self.tmp / "restored"
        self.write("y/pic.png", b"also occupied", base=alt)
        items = restore(self.journal, restore_to=alt)
        self.assertEqual(items[0].status, "restored")
        self.assertTrue(items[0].to_path.endswith("pic__duplicate_001.png"))
        self.assertEqual((alt / "y" / "pic.png").read_bytes(), b"also occupied")

    def test_restore_skips_modified_duplicate(self):
        self.stored.write_bytes(b"tampered")
        items = restore(self.journal)
        self.assertEqual(items[0].status, "skipped")
        self.assertFalse(self.b.exists())

    def test_restore_dry_run(self):
        items = restore(self.journal, dry_run=True)
        self.assertEqual(items[0].status, "planned")
        self.assertTrue(self.stored.exists())
        self.assertFalse(self.b.exists())


class JournalTests(TempTreeCase):
    def test_append_only_and_torn_line_tolerated(self):
        j = Journal(self.state / "j.jsonl")
        j.append("t1", "intent", kind="move", source="s")
        j.append("t1", "committed")
        size1 = j.path.stat().st_size
        with open(j.path, "ab") as fh:
            fh.write(b'{"tx": "t2", "ev')
        j.append("t3", "intent", kind="move", source="q")
        self.assertGreater(j.path.stat().st_size, size1)
        txs = j.transactions()
        self.assertTrue(txs["t1"].committed)
        self.assertIn("t3", txs)

    def test_exclusive_process_lock(self):
        j1 = Journal(self.state / "j.jsonl")
        j2 = Journal(self.state / "j.jsonl")
        j1.lock()
        try:
            from duplicate_finder.errors import JournalError
            if os.name == "nt":
                self.skipTest("msvcrt locks are per-handle; covered on POSIX")
            with self.assertRaises(JournalError):
                j2.lock()
        finally:
            j1.unlock()


if __name__ == "__main__":
    unittest.main()
