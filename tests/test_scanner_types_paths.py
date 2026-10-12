"""Scanning, type detection and path safety: spec §13 cases 7, 8, 17-20, 23."""

from __future__ import annotations

import os
import unittest
from pathlib import Path, PurePosixPath, PureWindowsPath
from unittest import mock

from duplicate_finder.config import Config, _mini_toml, load_config_file, apply_overrides
from duplicate_finder.errors import ConfigError, PathOutsideAllowedRoot
from duplicate_finder.file_types import FileTypeHandler, FormatSpec, new_registry
from duplicate_finder.models import IssueKind, MediaCategory, MoveStatus
from duplicate_finder.safety import assert_within, is_within, safe_relative, sanitize_component
from duplicate_finder.scanner import Scanner, normalise_roots

from tests.helpers import IS_ROOT, IS_WINDOWS, TempTreeCase, can_symlink


class FileTypeTests(unittest.TestCase):
    def setUp(self):
        self.reg = new_registry()

    def detect(self, header: bytes, ext: str):
        return self.reg.detect_header(header, ext)

    def test_signatures(self):
        cases = {
            (b"\xff\xd8\xff\xe0" + b"\x00" * 20, ".jpg"): ("image", "jpeg"),
            (b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, ".png"): ("image", "png"),
            (b"GIF89a" + b"\x00" * 20, ".gif"): ("image", "gif"),
            (b"RIFF\x00\x00\x00\x00WEBPVP8 ", ".webp"): ("image", "webp"),
            (b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00mif1heic", ".heic"): ("image", "heic"),
            (b"\x00\x00\x00\x1cftypavif\x00\x00\x00\x00avifmif1miaf", ".avif"): ("image", "avif"),
            (b"II*\x00\x08\x00\x00\x00CR\x02\x00", ".cr2"): ("image", "cr2"),
            (b"II*\x00\x08\x00\x00\x00\x00\x00", ".nef"): ("image", "nef"),
            (b"II*\x00\x08\x00\x00\x00\x00\x00", ".tif"): ("image", "tiff"),
            (b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2", ".mp4"): ("video", "mp4"),
            (b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ", ".mov"): ("video", "mov"),
            (b"\x00\x00\x00\x18ftyp3gp4\x00\x00\x00\x00", ".3gp"): ("video", "3gp"),
            (b"\x1aE\xdf\xa3\x9fB\x86\x81\x01B\xf7\x81\x01B\x82\x88matroska", ".mkv"): ("video", "mkv"),
            (b"\x1aE\xdf\xa3\x9fB\x82\x84webm", ".webm"): ("video", "webm"),
            (b"RIFF\x00\x00\x00\x00AVI LIST", ".avi"): ("video", "avi"),
            (b"0&\xb2u\x8ef\xcf\x11\xa6\xd9\x00\xaa\x00b\xcel", ".wmv"): ("video", "wmv"),
            (b"0&\xb2u\x8ef\xcf\x11\xa6\xd9\x00\xaa\x00b\xcel", ".wma"): ("audio", "wma"),
            (b"FLV\x01\x05", ".flv"): ("video", "flv"),
            (b"\x00\x00\x01\xba\x44", ".mpg"): ("video", "mpeg"),
            (b"ID3\x04\x00\x00\x00\x00\x00\x00\xff\xfb", ".mp3"): ("audio", "mp3"),
            (b"\xff\xfb\x90\x00", ".mp3"): ("audio", "mp3"),
            (b"RIFF\x00\x00\x00\x00WAVEfmt ", ".wav"): ("audio", "wav"),
            (b"fLaC\x00", ".flac"): ("audio", "flac"),
            (b"\xff\xf1\x50\x80", ".aac"): ("audio", "aac"),
            (b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00", ".m4a"): ("audio", "m4a"),
            (b"OggS\x00\x02" + b"\x00" * 22 + b"OpusHead", ".opus"): ("audio", "opus"),
            (b"OggS\x00\x02" + b"\x00" * 22 + b"\x01vorbis", ".ogg"): ("audio", "ogg"),
            (b"FORM\x00\x00\x00\x00AIFF", ".aiff"): ("audio", "aiff"),
        }
        for (header, ext), (cat, fmt) in cases.items():
            with self.subTest(ext=ext, fmt=fmt):
                info = self.detect(header, ext)
                self.assertEqual((info.category.value, info.format), (cat, fmt))
                self.assertEqual(info.detected_by, "signature")
                self.assertFalse(info.extension_mismatch)

    def test_iso_container_resolved_by_extension(self):
        hdr = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
        self.assertEqual(self.detect(hdr, ".m4a").category, MediaCategory.AUDIO)
        self.assertEqual(self.detect(hdr, ".alac").format, "m4a")

    def test_misleading_extension(self):  # case 8
        info = self.detect(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, ".mp3")
        self.assertEqual(info.format, "png")
        self.assertTrue(info.extension_mismatch)
        info = self.detect(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, ".txt")
        self.assertEqual(info.format, "png")
        self.assertFalse(info.extension_mismatch)

    def test_unknown_and_extension_only(self):
        self.assertEqual(self.detect(b"random bytes", ".xyz").detected_by, "none")
        info = self.detect(b"garbage not a jpeg", ".jpg")
        self.assertEqual((info.detected_by, info.format), ("extension", "jpeg"))
        self.assertEqual(self.detect(b"", "").category, MediaCategory.OTHER)

    def test_custom_handler_registration(self):
        class SvgHandler(FileTypeHandler):
            name = "svg"
            priority = 5
            formats = {"svg": FormatSpec(MediaCategory.IMAGE, "image/svg+xml", (".svg",))}

            def identify(self, header, extension):
                return "svg" if b"<svg" in header[:512].lower() else None

        self.reg.register(SvgHandler())
        info = self.detect(b"<?xml version='1.0'?><svg xmlns=...>", ".svg")
        self.assertEqual((info.format, info.handler), ("svg", "svg"))

    def test_broken_plugin_does_not_break_detection(self):
        class Broken(FileTypeHandler):
            name = "broken"
            priority = 1
            formats = {"x": FormatSpec(MediaCategory.OTHER, "x/x", (".x",))}

            def identify(self, header, extension):
                raise RuntimeError("boom")
        self.reg.register(Broken())
        self.assertEqual(self.detect(b"\x89PNG\r\n\x1a\n", ".png").format, "png")

    def test_plugin_module_loading(self):
        import sys
        import types
        mod = types.ModuleType("dupfinder_test_plugin")

        class H(FileTypeHandler):
            name = "txt"
            formats = {"text": FormatSpec(MediaCategory.OTHER, "text/plain", (".txt",))}

        mod.register = lambda registry: registry.register(H())
        sys.modules["dupfinder_test_plugin"] = mod
        try:
            self.reg.load_plugin_modules(["dupfinder_test_plugin"])
            self.assertIsNotNone(self.reg.get("txt"))
        finally:
            del sys.modules["dupfinder_test_plugin"]


class ScannerTests(TempTreeCase):
    def test_corrupt_and_misnamed_reported_not_fatal(self):  # cases 7, 8
        self.write("fake.jpg", b"definitely not a jpeg")
        self.write("real.mp3", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        self.write("ok.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
        r = self.run_engine(validate_media=True)
        kinds = {(Path(i.path).name, i.kind) for i in r.issues}
        self.assertIn(("real.mp3", IssueKind.EXTENSION_MISMATCH), kinds)
        self.assertIn(("fake.jpg", IssueKind.UNKNOWN_TYPE), kinds)
        self.assertEqual(r.files_scanned, 3)

    @unittest.skipIf(IS_WINDOWS or IS_ROOT, "POSIX permission bits not enforced (Windows or root)")
    def test_unreadable_file_and_dir_reported(self):  # case 18
        f = self.write("locked.bin", b"secret")
        self.write("copy.bin", b"secret")
        d = self.root / "lockeddir"
        d.mkdir()
        (d / "x.bin").write_bytes(b"x")
        os.chmod(f, 0)
        os.chmod(d, 0)
        r = self.run_engine()
        kinds = {(Path(i.path).name, i.kind) for i in r.issues}
        self.assertIn(("lockeddir", IssueKind.PERMISSION), kinds)
        self.assertIn(("locked.bin", IssueKind.PERMISSION), kinds)
        self.assertEqual(r.exact_groups, [])

    def test_permission_error_mocked(self):  # case 18 (portable)
        self.write("a.bin", b"perm")
        self.write("b.bin", b"perm")
        real_open = open

        def fake_open(path, *a, **k):
            if str(path).endswith("b.bin"):
                raise PermissionError(13, "Permission denied", str(path))
            return real_open(path, *a, **k)
        with mock.patch("builtins.open", fake_open):
            r = self.run_engine()
        self.assertEqual(r.exact_groups, [])
        self.assertTrue(any(i.kind is IssueKind.PERMISSION for i in r.issues))

    def test_symlinks_skipped_by_default(self):  # case 17
        if not can_symlink(self.tmp):
            self.skipTest("symlinks unavailable")
        target = self.write("real.bin", b"linked content")
        os.symlink(target, self.root / "link.bin")
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "o.bin").write_bytes(b"linked content")
        os.symlink(outside, self.root / "outside_link", target_is_directory=True)
        r = self.run_engine(action="auto")
        self.assertEqual(r.exact_groups, [])
        self.assertTrue(any(i.kind is IssueKind.SYMLINK_SKIPPED for i in r.issues))
        self.assertTrue((outside / "o.bin").exists())

    def test_follow_symlinks_within_roots_only(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks unavailable")
        target = self.write("sub/real.bin", b"linked content")
        os.symlink(target, self.root / "link.bin")  # alias of the same file, not a duplicate
        outside = self.tmp / "outside"
        outside.mkdir()
        (outside / "o.bin").write_bytes(b"linked content")
        os.symlink(outside, self.root / "outside_link", target_is_directory=True)
        os.symlink(self.root, self.root / "sub" / "loop", target_is_directory=True)
        r = self.run_engine(symlink_policy="follow-within-roots", action="auto")
        self.assertEqual(r.exact_groups, [], "a link to a file is not an independent copy")
        self.assertTrue((outside / "o.bin").exists(), "files outside the roots must never be touched")
        self.assertTrue(target.exists())

    def test_hardlinks_collapsed(self):  # case 17
        a = self.write("a.bin", b"hard")
        try:
            os.link(a, self.root / "b.bin")
        except OSError:
            self.skipTest("hard links unsupported")
        self.write("c.bin", b"hard")
        r = self.run_engine()
        self.assertEqual(len(r.exact_groups), 1)
        g = r.exact_groups[0]
        self.assertEqual(len(g.members), 2)
        self.assertTrue(any(m.aliases for m in g.members))

    def test_hardlinks_as_duplicates_option(self):
        a = self.write("a.bin", b"hard")
        try:
            os.link(a, self.root / "b.bin")
        except OSError:
            self.skipTest("hard links unsupported")
        r = self.run_engine(hardlinks_as_duplicates=True, action="auto")
        self.assertEqual(len(r.exact_groups), 1)
        self.assertEqual(r.moves[0].status, MoveStatus.MOVED)
        self.assertTrue(a.exists() or (self.root / "b.bin").exists())

    def test_excludes_and_size_filters(self):
        self.write(".git/objects/x", b"same")
        self.write("node_modules/y", b"same")
        self.write("keep/Thumbs.db", b"same")
        self.write("a.bin", b"same")
        self.write("big.bin", b"B" * 5000)
        self.write("big2.bin", b"B" * 5000)
        r = self.run_engine(min_size=10)
        self.assertEqual(len(r.exact_groups), 1)
        self.assertEqual(r.exact_groups[0].original.size, 5000)

    def test_nested_roots_deduplicated(self):
        self.write("sub/a.bin", b"n")
        roots, warnings = normalise_roots([self.root, self.root / "sub"])
        self.assertEqual(roots, [self.root])
        self.assertTrue(warnings)

    def test_stability_window(self):
        self.write("a.bin", b"fresh")
        self.write("b.bin", b"fresh")
        r = self.run_engine(stability_seconds=3600)
        self.assertEqual(r.exact_groups, [])
        self.assertTrue(all(i.kind is IssueKind.UNSTABLE for i in r.issues))

    def test_missing_root(self):
        with self.assertRaises(ConfigError):
            self.run_engine(roots=[self.tmp / "nope"])


class PathSafetyTests(TempTreeCase):  # cases 20, 23
    def test_sanitize_component(self):
        self.assertEqual(sanitize_component("../../etc/passwd"), ".._.._etc_passwd")
        self.assertEqual(sanitize_component(".."), "file")
        self.assertEqual(sanitize_component("CON.txt"), "_CON.txt")
        self.assertEqual(sanitize_component("lpt1"), "_lpt1")
        self.assertEqual(sanitize_component('a<b>c:d"e|f?g*h'), "a_b_c_d_e_f_g_h")
        self.assertEqual(sanitize_component("trailing. . "), "trailing")
        self.assertEqual(sanitize_component("bell\x07name"), "bell_name")
        long = "é" * 300 + ".jpg"
        out = sanitize_component(long)
        self.assertLessEqual(len(out.encode("utf-8")), 200)
        self.assertTrue(out.endswith(".jpg"))
        # NFC normalisation: macOS NFD names map to the same component
        self.assertEqual(sanitize_component("e\u0301.jpg"), "\u00e9.jpg")

    def test_safe_relative_neutralises_traversal(self):
        for raw in ["../../x", "/etc/passwd", "a/../../b", "C:\\Windows\\x", "\\\\server\\share\\f"]:
            rel = safe_relative(raw)
            self.assertFalse(rel.is_absolute(), raw)
            self.assertNotIn("..", rel.parts, raw)
            joined = self.dest / rel
            self.assertTrue(is_within(joined, self.dest), raw)

    def test_windows_and_posix_path_shapes(self):
        # Pure path classes let us check behaviour for other OSes on any host.
        self.assertEqual(PureWindowsPath(r"C:\Photos\a.jpg").name, "a.jpg")
        # A backslash separates folders only on Windows; elsewhere it is a legal
        # filename character and is neutralised into the name.
        expected = "a.jpg" if IS_WINDOWS else "Photos_2024_a.jpg"
        self.assertEqual(safe_relative(str(PureWindowsPath(r"Photos\2024\a.jpg"))).name, expected)
        self.assertEqual(safe_relative(str(PurePosixPath("Photos/2024/a.jpg"))).parts[-2:], ("2024", "a.jpg"))

    def test_assert_within_with_symlink_escape(self):
        if not can_symlink(self.tmp):
            self.skipTest("symlinks unavailable")
        self.dest.mkdir()
        os.symlink(self.tmp, self.dest / "escape", target_is_directory=True)
        with self.assertRaises(PathOutsideAllowedRoot):
            assert_within(self.dest / "escape" / "x", self.dest)
        assert_within(self.dest / "Images" / "x", self.dest)

    def test_malicious_file_names_on_disk(self):
        if IS_WINDOWS:
            names = ["con_like CON.jpg", "dots...jpg"]
        else:
            names = ["-rf.jpg", "--help.jpg", "a\\b.jpg", "new\nline.jpg", "$(touch pwned).jpg"]
        for n in names:
            self.write(f"x/{n}", b"\xff\xd8\xff" + b"m" * 10)
            self.write(f"y/{n}", b"\xff\xd8\xff" + b"m" * 10)
        r = self.run_engine(action="auto")
        for mv in r.moves:
            self.assertTrue(is_within(mv.destination, self.dest))
            self.assertIn(mv.status, (MoveStatus.MOVED,))
        self.assertFalse((self.tmp / "pwned").exists())


class ConfigTests(TempTreeCase):
    def test_sample_config_parses(self):
        sample = Path(__file__).resolve().parent.parent / "config.sample.toml"
        data = load_config_file(sample)
        cfg = apply_overrides(Config(), data)
        cfg.validate()
        self.assertEqual(cfg.mode, "exact")

    def test_mini_toml_matches_tomllib(self):
        sample = (Path(__file__).resolve().parent.parent / "config.sample.toml").read_text(encoding="utf-8")
        try:
            import tomllib
        except ImportError:
            self.skipTest("tomllib unavailable")
        self.assertEqual(_mini_toml(sample), tomllib.loads(sample))

    def test_invalid_values_rejected(self):
        for kw in ({"mode": "fuzzy"}, {"workers": 0}, {"layout": "../x"}, {"keep": ["random"]},
                   {"category_dirs": {"image": "../evil", "video": "V", "audio": "A", "other": "O"}}):
            with self.subTest(kw=kw):
                cfg = self.config(**kw)
                with self.assertRaises(ConfigError):
                    cfg.validate()


if __name__ == "__main__":
    unittest.main()
