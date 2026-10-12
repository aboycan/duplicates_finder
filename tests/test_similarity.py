"""Similarity detection: spec §13 cases 9, 10, 11."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from duplicate_finder.config import Config
from duplicate_finder.detectors.audio import AudioSimilarityDetector, _env_similarity
from duplicate_finder.detectors.base import build_groups
from duplicate_finder.detectors.video import VideoSimilarityDetector
from duplicate_finder.models import FileRecord, MatchClass, MediaCategory, MoveStatus, StatFingerprint, FileTypeInfo

from tests.helpers import HAVE_PIL, TempTreeCase, have_ffmpeg, make_image, make_wav


def _rec(path, cat=MediaCategory.VIDEO):
    st = os.stat(path)
    r = FileRecord(path=path, root=path.parent, fingerprint=StatFingerprint.from_stat(st))
    r.type_info = FileTypeInfo(cat, "x", "x/x", "signature", path.suffix)
    return r


@unittest.skipUnless(HAVE_PIL, "Pillow not installed")
class ImageSimilarityTests(TempTreeCase):
    def test_same_image_different_encodings(self):  # case 9
        make_image(self.root / "orig.png", seed=7)
        make_image(self.root / "copy.jpg", seed=7, quality=85)
        make_image(self.root / "small.webp", seed=7, size=(128, 96), quality=80)
        r = self.run_engine(mode="all")
        self.assertEqual(r.exact_groups, [], "different encodings are never exact duplicates")
        self.assertEqual(len(r.similar_groups), 1)
        g = r.similar_groups[0]
        self.assertEqual(len(g.members), 3)
        self.assertIn(g.match_class, (MatchClass.PROBABLE, MatchClass.REVIEW))
        self.assertNotEqual(g.match_class, MatchClass.EXACT)

    def test_different_images_not_matched(self):  # case 10
        for seed in range(1, 6):
            make_image(self.root / f"img{seed}.png", seed=seed * 101)
        r = self.run_engine(mode="similarity")
        self.assertEqual(r.similar_groups, [])

    def test_edited_image_never_exact_and_never_auto_moved(self):  # case 10
        a = make_image(self.root / "a.png", seed=3)
        b = make_image(self.root / "b.png", seed=3, overlay=True)
        before = self.snapshot()
        r = self.run_engine(mode="all", action="auto")
        self.assertEqual(r.exact_groups, [])
        for g in r.similar_groups:
            self.assertNotEqual(g.match_class, MatchClass.EXACT)
        self.assertEqual(self.snapshot(), before, "similar images must not be moved automatically")
        self.assertTrue(a.exists() and b.exists())

    def test_interactive_explicit_approval_moves_similar(self):
        make_image(self.root / "a.png", seed=9)
        b = make_image(self.root / "b.jpg", seed=9, quality=80)
        os.utime(self.root / "a.png", (1, 1))

        def approver(moves, groups):
            for m in moves:
                m.status = MoveStatus.APPROVED
            return True
        r = self.run_engine(mode="similarity", action="interactive", approver=approver)
        self.assertEqual(r.moves[0].status, MoveStatus.MOVED)
        self.assertFalse(b.exists())
        self.assertTrue((self.root / "a.png").exists())

    def test_corrupt_image_reported(self):
        self.write("broken.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 30)
        make_image(self.root / "ok.png", seed=1)
        r = self.run_engine(mode="similarity")
        self.assertTrue(any("broken.png" in str(i.path) for i in r.issues))


class AudioSimilarityTests(TempTreeCase):
    def test_same_audio_different_metadata(self):  # case 11
        make_wav(self.root / "a.wav", info_title="Track A")
        make_wav(self.root / "b.wav", info_title="Totally different title")
        make_wav(self.root / "c.wav", freq_seed=5)
        r = self.run_engine(mode="all")
        self.assertEqual(r.exact_groups, [], "metadata differs, so bytes differ: not exact")
        if not have_ffmpeg():
            self.skipTest("ffmpeg not installed: only metadata-based review hints available")
        groups = [g for g in r.similar_groups if g.category is MediaCategory.AUDIO]
        self.assertEqual(len(groups), 1)
        names = sorted(m.path.name for m in groups[0].members)
        self.assertEqual(names, ["a.wav", "b.wav"])
        self.assertIs(groups[0].match_class, MatchClass.PROBABLE)

    def test_metadata_only_never_probable(self):
        cfg = Config()
        det = AudioSimilarityDetector(cfg)
        a = _rec(make_wav(self.root / "x.wav"), MediaCategory.AUDIO)
        b = _rec(make_wav(self.root / "y.wav", freq_seed=3), MediaCategory.AUDIO)
        fa = {"meta": {"title": "Song", "artist": "Band", "duration": 3.0}, "duration": 3.0}
        fb = {"meta": {"title": "song!", "artist": "band", "duration": 3.0}, "duration": 3.0}
        m = det._compare(a, b, fa, fb, 0.0)
        self.assertIsNotNone(m)
        self.assertIs(m.match_class, MatchClass.REVIEW)
        fb["meta"]["title"] = "Other"
        self.assertIsNone(det._compare(a, b, fa, fb, 0.0))

    def test_envelope_similarity(self):
        import math
        base = [math.sin(i / 3.0) + 2 for i in range(200)]
        shifted = [0.0, 0.0] + base[:-2]
        self.assertGreater(_env_similarity(base, shifted), 0.99)
        self.assertIsNone(_env_similarity([1.0] * 100, [1.0] * 100), "silence carries no evidence")


class VideoSimilarityTests(TempTreeCase):
    def test_metadata_alone_never_matches(self):  # case 11 (video)
        a = _rec(self.write("a.mp4", b"\x00\x00\x00\x18ftypisom" + b"1" * 100))
        b = _rec(self.write("b.mp4", b"\x00\x00\x00\x18ftypisom" + b"2" * 100))
        det = VideoSimilarityDetector(Config(video_samples=3))
        meta = {"duration": 10.0, "width": 1920, "height": 1080, "fps": 30.0}
        with mock.patch("duplicate_finder.media_probe.ffprobe_summary", return_value=dict(meta)), \
                mock.patch("duplicate_finder.media_probe.extract_frame_png", return_value=None):
            matches = det.find_matches([a, b])
        self.assertEqual(matches, [])
        self.assertEqual(len(det.issues), 2)

    @unittest.skipUnless(HAVE_PIL, "Pillow not installed")
    def test_frame_hashes_decide(self):
        import io
        from PIL import Image
        from tests.helpers import make_image
        a = _rec(self.write("a.mp4", b"x" * 10))
        b = _rec(self.write("b.mkv", b"y" * 10))
        c = _rec(self.write("c.avi", b"z" * 10))
        frames = {}
        for name, seed in (("a.mp4", 1), ("b.mkv", 1), ("c.avi", 50)):
            p = make_image(self.tmp / f"{name}.png", seed=seed)
            frames[name] = p.read_bytes()

        def probe(path, timeout=60):
            return {"duration": 12.0, "width": 640, "height": 480, "fps": 25.0}

        def frame(path, at, width=64, timeout=60):
            return frames[path.name]
        det = VideoSimilarityDetector(Config(video_samples=3))
        with mock.patch("duplicate_finder.media_probe.ffprobe_summary", probe), \
                mock.patch("duplicate_finder.media_probe.extract_frame_png", frame):
            matches = det.find_matches([a, b, c])
        self.assertEqual(len(matches), 1)
        self.assertEqual({matches[0].a.path.name, matches[0].b.path.name}, {"a.mp4", "b.mkv"})
        self.assertIs(matches[0].match_class, MatchClass.PROBABLE)
        groups = build_groups(matches, Config(), [self.root])
        self.assertEqual(len(groups), 1)

    @unittest.skipUnless(have_ffmpeg() and HAVE_PIL, "ffmpeg not installed")
    def test_real_transcoded_video(self):
        import subprocess
        src = self.root / "clip.mp4"
        subprocess.run(["ffmpeg", "-v", "error", "-f", "lavfi", "-i", "testsrc=duration=4:size=320x240:rate=25",
                        "-pix_fmt", "yuv420p", str(src)], check=True)
        subprocess.run(["ffmpeg", "-v", "error", "-i", str(src), "-vf", "scale=160:120", "-b:v", "100k",
                        str(self.root / "clip_small.mkv")], check=True)
        r = self.run_engine(mode="all", video_samples=3)
        self.assertEqual(r.exact_groups, [])
        vids = [g for g in r.similar_groups if g.category is MediaCategory.VIDEO]
        self.assertEqual(len(vids), 1, r.detector_status)


if __name__ == "__main__":
    unittest.main()
