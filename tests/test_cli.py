"""End-to-end CLI tests (interactive mode with scripted answers, recover, restore, manifest)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from duplicate_finder.cli import main

from tests.helpers import TempTreeCase

PROJECT = Path(__file__).resolve().parent.parent


class CliTests(TempTreeCase):
    def cli(self, *args, answers=()):
        it = iter(answers)
        out = io.StringIO()
        code = main([*args], input_fn=lambda prompt: next(it), out=out)
        return code, out.getvalue()

    def base(self, *extra):
        return ["scan", str(self.root), "--destination", str(self.dest), "--state-dir", str(self.state), "-q", *extra]

    def test_dry_run_default(self):
        self.write("a/x.jpg", b"\xff\xd8\xff" + b"1" * 10)
        self.write("b/x.jpg", b"\xff\xd8\xff" + b"1" * 10)
        before = self.snapshot()
        code, out = self.cli(*self.base())
        self.assertEqual(code, 0)
        self.assertIn("Verified exact duplicate groups: 1", out)
        self.assertIn("No files were changed (dry run)", out)
        self.assertEqual(self.snapshot(), before)

    def test_json_report(self):
        self.write("a.bin", b"r" * 5)
        self.write("b.bin", b"r" * 5)
        code, out = self.cli(*self.base("--report", "json", "--redact-paths"))
        self.assertEqual(code, 0)
        reports = list((self.state / "reports").glob("*.json"))
        self.assertEqual(len(reports), 1)
        data = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(data["summary"]["exact_groups"], 1)
        g = data["exact_groups"][0]
        for key in ("group_id", "original", "duplicates", "size", "sha256", "match_class", "confidence",
                    "media_type"):
            self.assertIn(key, g)
        for key in ("destination", "status", "timestamp", "reason"):
            self.assertIn(key, g["duplicates"][0])

    def test_interactive_approve_and_reject(self):
        k = self.write("k/a.bin", b"I" * 10)
        os.utime(k, (1, 1))
        d1 = self.write("x/a.bin", b"I" * 10)
        d2 = self.write("y/a.bin", b"I" * 10)
        # approve first, reject second, then confirm
        code, out = self.cli(*self.base("--interactive"), answers=["y", "n", "y"])
        self.assertEqual(code, 0)
        self.assertEqual(sum(p.exists() for p in (d1, d2)), 1)
        self.assertTrue(k.exists())

    def test_interactive_decline_confirmation_changes_nothing(self):
        self.write("a.bin", b"N" * 10)
        self.write("b.bin", b"N" * 10)
        before = self.snapshot()
        code, _ = self.cli(*self.base("--interactive"), answers=["y", "n"])
        self.assertEqual(self.snapshot(), before)

    def test_auto_manifest_restore(self):
        k = self.write("k/a.bin", b"M" * 10)
        os.utime(k, (1, 1))
        d = self.write("x/a.bin", b"M" * 10)
        code, out = self.cli(*self.base("--auto"))
        self.assertEqual(code, 0)
        self.assertFalse(d.exists())
        code, out = self.cli("manifest", "--state-dir", str(self.state))
        self.assertIn(str(d), out)
        code, out = self.cli("restore", "--state-dir", str(self.state), "-y")
        self.assertEqual(code, 0, out)
        self.assertTrue(d.exists())

    def test_recover_nothing(self):
        code, out = self.cli("recover", "--state-dir", str(self.state))
        self.assertEqual(code, 0)
        self.assertIn("Nothing to do", out)

    def test_cache_and_types(self):
        self.assertEqual(self.cli("cache", "stats", "--state-dir", str(self.state))[0], 0)
        code, out = self.cli("types", "--state-dir", str(self.state))
        self.assertEqual(code, 0)
        self.assertIn("jpeg", out)

    def test_bad_arguments(self):
        code, _ = self.cli("scan", str(self.tmp / "missing"), "--state-dir", str(self.state), "-q")
        self.assertEqual(code, 2)
        with self.assertRaises(SystemExit):
            self.cli("scan")

    def test_python_dash_m_entry_point(self):
        self.write("a.bin", b"E" * 3)
        self.write("b.bin", b"E" * 3)
        env = dict(os.environ, PYTHONPATH=str(PROJECT), DUPFINDER_STATE_DIR=str(self.state))
        proc = subprocess.run([sys.executable, "-m", "duplicate_finder", "scan", str(self.root), "-q",
                               "--report", "none"], capture_output=True, text=True, env=env, cwd=str(self.tmp),
                              timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Verified exact duplicate groups: 1", proc.stdout)


if __name__ == "__main__":
    unittest.main()
