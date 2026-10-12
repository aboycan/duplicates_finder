"""Exact (binary) duplicate detection: spec §13 cases 1-6, 24 and acceptance criteria."""

from __future__ import annotations

import os
import time
import unittest
from pathlib import Path

from duplicate_finder.database import Database
from duplicate_finder.grouping import ExactMatcher, select_original
from duplicate_finder.hashing import files_identical, partial_hash, sha256_file
from duplicate_finder.models import FileRecord, MatchClass, StatFingerprint
from duplicate_finder.scanner import Scanner

from tests.helpers import TempTreeCase


def _paths(group):
    return sorted(str(m.path) for m in group.members)


class ExactMatchingTests(TempTreeCase):
    def test_identical_files_same_name_different_dirs(self):  # case 1
        a = self.write("a/photo.jpg", b"\xff\xd8\xff" + b"A" * 1000)
        b = self.write("b/photo.jpg", b"\xff\xd8\xff" + b"A" * 1000)
        r = self.run_engine()
        self.assertEqual(len(r.exact_groups), 1)
        self.assertEqual(_paths(r.exact_groups[0]), sorted([str(a), str(b)]))
        self.assertIs(r.exact_groups[0].match_class, MatchClass.EXACT)

    def test_identical_files_different_names(self):  # case 2
        self.write("x/one.bin", b"same content" * 100)
        self.write("y/two.dat", b"same content" * 100)
        self.write("y/three", b"same content" * 100)
        r = self.run_engine()
        self.assertEqual(len(r.exact_groups), 1)
        self.assertEqual(len(r.exact_groups[0].duplicates), 2)

    def test_different_files_same_name(self):  # case 3
        self.write("a/photo.jpg", b"\xff\xd8\xff" + b"A" * 500)
        self.write("b/photo.jpg", b"\xff\xd8\xff" + b"B" * 700)
        self.assertEqual(self.run_engine().exact_groups, [])

    def test_different_files_same_size(self):  # case 4
        self.write("a.bin", b"A" * 4096 + b"1")
        self.write("b.bin", b"A" * 4096 + b"2")
        r = self.run_engine()
        self.assertEqual(r.exact_groups, [])
        self.assertEqual(r.stats["candidates"], 2)

    def test_same_size_large_differing_only_in_middle(self):
        # Partial hash (first+last 64 KiB) matches; full hash must still separate them.
        base = os.urandom(1024 * 1024)
        mid = len(base) // 2
        self.write("a.bin", base)
        self.write("b.bin", base[:mid] + bytes([base[mid] ^ 0xFF]) + base[mid + 1:])
        self.assertEqual(self.run_engine().exact_groups, [])

    def test_empty_files_are_exact_duplicates(self):  # case 5
        self.write("e1.txt", b"")
        self.write("sub/e2.log", b"")
        r = self.run_engine()
        self.assertEqual(len(r.exact_groups), 1)
        self.assertEqual(r.exact_groups[0].original.size, 0)

    def test_large_file_chunked(self):  # case 6
        data = os.urandom(3 * 1024 * 1024 + 123)
        a = self.write("big1.bin", data)
        self.write("big2.bin", data)
        # chunk smaller than the file forces many reads
        digest, _ = sha256_file(a, chunk_size=4096)
        import hashlib
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())
        r = self.run_engine(chunk_size=8192, verify="bytes")
        self.assertEqual(len(r.exact_groups), 1)
        self.assertEqual(r.exact_groups[0].verified_by, "sha256+bytes")

    def test_byte_verification_detects_hash_collision(self):
        # Simulate a (theoretical) SHA-256 collision: byte mode must split the group.
        a = self.write("a.bin", b"x" * 100)
        b = self.write("b.bin", b"y" * 100)
        cfg = self.config(verify="bytes")
        recs = Scanner(cfg).scan().records
        issues = []
        db = Database(self.state / "db.sqlite3", enabled=False)
        m = ExactMatcher(cfg, db, [self.root], issues)
        for r in recs:
            r.sha256 = "0" * 64
        clusters = m._byte_verify(recs)
        self.assertEqual(len(clusters), 2)
        self.assertTrue(files_identical(a, a))
        self.assertFalse(files_identical(a, b))

    def test_three_way_and_multiple_groups(self):
        for i in range(3):
            self.write(f"g1/{i}.bin", b"group one")
        for i in range(2):
            self.write(f"g2/{i}.bin", b"group two!")
        self.write("unique.bin", b"unique123")
        r = self.run_engine()
        self.assertEqual(sorted(len(g.members) for g in r.exact_groups), [2, 3])


class OriginalSelectionTests(TempTreeCase):
    def test_deterministic_and_documented(self):
        old = self.write("z/old.bin", b"content")
        new = self.write("a/new.bin", b"content")
        t = time.time()
        os.utime(old, (t - 1000, t - 1000))
        os.utime(new, (t, t))
        cfg = self.config()
        recs = Scanner(cfg).scan().records
        orig, others, reason = select_original(recs, cfg, [self.root])
        self.assertEqual(orig.path, old)
        self.assertIn("oldest", reason)
        # Order of input must not matter
        orig2, _, _ = select_original(list(reversed(recs)), cfg, [self.root])
        self.assertEqual(orig2.path, old)

    def test_prefer_paths_and_root_order(self):
        r2 = self.tmp / "second"
        self.write("x.bin", b"data")
        self.write("x.bin", b"data", base=r2)
        cfg = self.config(roots=[self.root, r2], keep=["root-order", "path"])
        res = self.run_engine(roots=[self.root, r2], keep=["root-order", "path"])
        self.assertTrue(str(res.exact_groups[0].original.path).startswith(str(self.root)))
        res = self.run_engine(roots=[self.root, r2], keep=["prefer-paths", "root-order"], prefer_paths=[r2])
        self.assertTrue(str(res.exact_groups[0].original.path).startswith(str(r2)))
        del cfg


class CacheTests(TempTreeCase):
    def test_cache_not_trusted_without_change_time(self):
        from unittest import mock
        self.write("a.bin", b"1" * 5000)
        self.write("b.bin", b"1" * 5000)
        self.run_engine()
        with mock.patch("duplicate_finder.grouping.CTIME_IS_CHANGE_TIME", False):
            r = self.run_engine()
        self.assertEqual(r.stats["cache_hits"], 0)
        self.assertEqual(r.stats["full_hashed"], 2)

    @unittest.skipIf(os.name == "nt", "full-hash cache is not trusted on Windows (ctime is creation time)")
    def test_cache_hit_and_invalidation(self):  # case 24 (stale cache)
        a = self.write("a.bin", b"1" * 5000)
        b = self.write("b.bin", b"1" * 5000)
        r1 = self.run_engine()
        self.assertEqual(r1.stats["full_hashed"], 2)
        r2 = self.run_engine()
        self.assertEqual(r2.stats["cache_hits"], 2)
        self.assertEqual(len(r2.exact_groups), 1)
        self.assertIn("cache", r2.exact_groups[0].verified_by)
        # Modify b keeping size and even restoring mtime: ctime/ino still differ or content hashed anew.
        st = os.stat(b)
        b.write_bytes(b"2" * 5000)
        os.utime(b, ns=(st.st_atime_ns, st.st_mtime_ns))
        r3 = self.run_engine()
        self.assertEqual(r3.exact_groups, [], "stale cache entry must not create a false duplicate")
        del a

    def test_cache_disabled(self):
        self.write("a.bin", b"q" * 100)
        self.write("b.bin", b"q" * 100)
        self.run_engine()  # populate
        r = self.run_engine(use_cache=False)
        self.assertEqual(r.stats["cache_hits"], 0)
        self.assertEqual(r.stats["full_hashed"], 2)

    def test_stale_entry_rejected_by_fingerprint(self):
        p = self.write("f.bin", b"abc")
        db = Database(self.state / "s.sqlite3")
        fp = StatFingerprint.from_stat(os.stat(p))
        db.put_hashes([(p, fp, None, "deadbeef")])
        self.assertEqual(db.get_cached(p, fp)[1], "deadbeef")
        changed = StatFingerprint(fp.dev, fp.ino, fp.size, fp.mtime_ns + 1, fp.ctime_ns)
        self.assertIsNone(db.get_cached(p, changed)[1])
        db.close()

    def test_unsigned_64bit_file_ids(self):
        # NTFS file IDs / volume serials can exceed SQLite's signed 64-bit INTEGER.
        p = self.write("f.bin", b"abc")
        db = Database(self.state / "big.sqlite3")
        fp = StatFingerprint(dev=(1 << 64) - 5, ino=(1 << 63) + 12345, size=3, mtime_ns=1, ctime_ns=2)
        db.put_hashes([(p, fp, "partial", "beef")])
        self.assertEqual(db.get_cached(p, fp), ("partial", "beef"))
        other = StatFingerprint(dev=fp.dev, ino=fp.ino - 1, size=3, mtime_ns=1, ctime_ns=2)
        self.assertEqual(db.get_cached(p, other), (None, None))
        db.close()

    def test_corrupt_database_is_quarantined_not_deleted(self):  # case 24 (corruption)
        self.state.mkdir(parents=True, exist_ok=True)
        dbp = self.state / "state.sqlite3"
        dbp.write_bytes(b"this is not a sqlite database" * 100)
        self.write("a.bin", b"z" * 10)
        self.write("b.bin", b"z" * 10)
        r = self.run_engine()
        self.assertEqual(len(r.exact_groups), 1)
        self.assertTrue(any("corrupt" in w for w in r.warnings))
        aside = [p for p in self.state.iterdir() if ".corrupt-" in p.name]
        self.assertTrue(aside, "corrupt database must be preserved aside")


class HashingTests(TempTreeCase):
    def test_change_during_hashing_detected(self):
        from duplicate_finder.errors import SourceChanged
        p = self.write("f.bin", b"a" * 10000)
        fp = StatFingerprint.from_stat(os.stat(p))
        time.sleep(0.01)
        p.write_bytes(b"b" * 10001)
        with self.assertRaises(SourceChanged):
            sha256_file(p, expected=fp)
        with self.assertRaises(SourceChanged):
            partial_hash(p, expected=fp)


if __name__ == "__main__":
    unittest.main()
