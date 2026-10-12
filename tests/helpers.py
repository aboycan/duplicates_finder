"""Shared test utilities (stdlib only, so tests run under pytest *or* unittest)."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import struct
import sys
import tempfile
import unittest
import wave
from pathlib import Path
from typing import Dict, Optional, Tuple

from duplicate_finder.config import Config
from duplicate_finder.pipeline import Engine, RunResult
from duplicate_finder.runtime import CancelToken, Progress

try:
    from PIL import Image, ImageDraw
    HAVE_PIL = True
except ImportError:  # pragma: no cover
    HAVE_PIL = False

IS_WINDOWS = sys.platform.startswith("win")
IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


def can_symlink(tmp: Path) -> bool:
    try:
        (tmp / "_probe_target").write_text("x")
        os.symlink(tmp / "_probe_target", tmp / "_probe_link")
        return True
    except (OSError, NotImplementedError):
        return False


class TempTreeCase(unittest.TestCase):
    """Creates ``self.tmp`` with ``root/`` (scanned) and ``state/`` (app state)."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="dupfinder-test-")
        self.tmp = Path(self._td.name)
        self.root = self.tmp / "root"
        self.root.mkdir()
        self.state = self.tmp / "state"
        self.dest = self.tmp / "Duplicates"

    def tearDown(self) -> None:
        # Restore permissions changed by tests so cleanup can proceed.
        for dirpath, dirnames, filenames in os.walk(self.tmp):
            for n in dirnames + filenames:
                try:
                    os.chmod(os.path.join(dirpath, n), 0o700)
                except OSError:
                    pass
        self._td.cleanup()

    # -- builders --------------------------------------------------------------
    def write(self, rel: str, data: bytes, base: Optional[Path] = None) -> Path:
        p = (base or self.root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def config(self, **kw) -> Config:
        cfg = Config(roots=[self.root], destination=self.dest, state_dir=self.state, progress=False,
                     report_formats=[], workers=2)
        for k, v in kw.items():
            setattr(cfg, k, v)
        return cfg

    def run_engine(self, approver=None, cancel: Optional[CancelToken] = None, **kw) -> RunResult:
        return Engine(self.config(**kw), cancel=cancel, progress=Progress(False)).run(approver)

    # -- assertions --------------------------------------------------------------
    def snapshot(self, base: Optional[Path] = None) -> Dict[str, Tuple[str, int, int]]:
        base = base or self.tmp
        snap = {}
        for dirpath, dirnames, filenames in os.walk(base):
            if Path(dirpath) == self.state or self.state in Path(dirpath).parents:
                continue
            for n in filenames:
                p = Path(dirpath) / n
                st = os.lstat(p)
                digest = hashlib.sha256(p.read_bytes()).hexdigest() if not os.path.islink(p) else "link"
                snap[str(p.relative_to(base))] = (digest, st.st_size, st.st_mtime_ns)
            for n in dirnames:
                if Path(dirpath) / n == self.state:
                    continue
                snap[str((Path(dirpath) / n).relative_to(base)) + "/"] = ("dir", 0, 0)
        return snap

    def all_content_hashes(self) -> Dict[str, int]:
        """Multiset of content hashes across the whole temp tree (excluding state)."""
        counts: Dict[str, int] = {}
        for k, (digest, _, _) in self.snapshot().items():
            if digest != "dir":
                counts[digest] = counts.get(digest, 0) + 1
        return counts


# ---------------------------------------------------------------------- media generators

def make_image(path: Path, seed: int = 1, size=(256, 192), fmt: Optional[str] = None,
               quality: int = 90, overlay: bool = False) -> Path:
    """Deterministic synthetic photo-like image."""
    img = Image.new("RGB", size, (20, 30, 40))
    d = ImageDraw.Draw(img)
    w, h = size
    import random
    rnd = random.Random(seed)
    for _ in range(12):
        x0, y0 = rnd.randint(0, w - 1), rnd.randint(0, h - 1)
        x1, y1 = rnd.randint(x0, w), rnd.randint(y0, h)
        d.rectangle([x0, y0, x1, y1], fill=(rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(0, 255)))
    for _ in range(6):
        x, y, r = rnd.randint(0, w), rnd.randint(0, h), rnd.randint(5, w // 4)
        d.ellipse([x - r, y - r, x + r, y + r], fill=(rnd.randint(0, 255), rnd.randint(0, 255), rnd.randint(0, 255)))
    if overlay:
        d.rectangle([w // 3, h // 3, w // 3 + w // 5, h // 3 + h // 5], fill=(255, 255, 255))
    path.parent.mkdir(parents=True, exist_ok=True)
    kwargs = {"quality": quality} if (fmt or path.suffix.lower().lstrip(".")) in ("jpeg", "jpg", "webp") else {}
    img.save(path, format=fmt, **kwargs)
    return path


def make_wav(path: Path, seconds: float = 3.0, freq_seed: int = 1, rate: int = 8000,
             info_title: Optional[str] = None) -> Path:
    """Synthetic audio with a varying envelope; optional RIFF INFO metadata chunk."""
    import math
    frames = bytearray()
    n = int(seconds * rate)
    for i in range(n):
        t = i / rate
        env = 0.5 + 0.5 * math.sin(2 * math.pi * (0.7 + 0.13 * freq_seed) * t)
        s = env * math.sin(2 * math.pi * (220 + 40 * freq_seed) * t) * 0.6
        frames += struct.pack("<h", int(s * 32767))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
    data = buf.getvalue()
    if info_title is not None:
        title = info_title.encode() + b"\x00"
        if len(title) % 2:
            title += b"\x00"
        inam = b"INAM" + struct.pack("<I", len(title)) + title
        lst = b"LIST" + struct.pack("<I", 4 + len(inam)) + b"INFO" + inam
        body = data[12:] + lst
        data = b"RIFF" + struct.pack("<I", 4 + len(body)) + b"WAVE" + body
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def have_ffmpeg() -> bool:
    return bool(shutil.which("ffmpeg") and shutil.which("ffprobe"))
