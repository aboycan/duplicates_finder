"""Perceptual image similarity (pHash + dHash, dimensions as supporting evidence).

Uses ``ImageHash`` when installed, otherwise a built-in pure-Python pHash/dHash
on top of Pillow.  HEIC/AVIF need ``pillow-heif`` / ``pillow-avif-plugin``.
"""

from __future__ import annotations

import math
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from ..grouping import bounded_map
from ..models import FileRecord, MatchClass, MediaCategory
from .base import SimilarityDetector, SimilarityMatch, hamming

try:  # optional
    from PIL import Image, ImageOps
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    ImageOps = None  # type: ignore

try:  # optional
    import imagehash  # type: ignore
except ImportError:
    imagehash = None

try:  # optional HEIC/HEIF support
    import pillow_heif  # type: ignore
    pillow_heif.register_heif_opener()
except Exception:  # noqa: BLE001
    pass
try:  # optional AVIF support (older Pillow)
    import pillow_avif  # type: ignore  # noqa: F401
except Exception:  # noqa: BLE001
    pass


@lru_cache(maxsize=4)
def _dct_matrix(n: int) -> List[List[float]]:
    m = []
    for k in range(n):
        scale = math.sqrt(1.0 / n) if k == 0 else math.sqrt(2.0 / n)
        m.append([scale * math.cos(math.pi * (2 * i + 1) * k / (2 * n)) for i in range(n)])
    return m


def _bits_to_int(bits: Sequence[bool]) -> int:
    v = 0
    for b in bits:
        v = (v << 1) | int(b)
    return v


def phash_builtin(img: "Image.Image", hash_size: int = 8, factor: int = 4) -> int:
    n = hash_size * factor
    g = img.convert("L").resize((n, n), Image.LANCZOS)
    px = list(g.getdata())
    rows = [px[i * n:(i + 1) * n] for i in range(n)]
    d = _dct_matrix(n)
    # 2-D DCT, only the low-frequency hash_size x hash_size block is needed.
    tmp = [[sum(d[k][i] * rows[r][i] for i in range(n)) for k in range(hash_size)] for r in range(n)]
    low = [[sum(d[k][r] * tmp[r][c] for r in range(n)) for c in range(hash_size)] for k in range(hash_size)]
    flat = [v for row in low for v in row]
    med = sorted(flat)[len(flat) // 2]
    return _bits_to_int([v > med for v in flat])


def dhash_builtin(img: "Image.Image", hash_size: int = 8) -> int:
    g = img.convert("L").resize((hash_size + 1, hash_size), Image.LANCZOS)
    px = list(g.getdata())
    bits = []
    for r in range(hash_size):
        row = px[r * (hash_size + 1):(r + 1) * (hash_size + 1)]
        bits.extend(row[c + 1] > row[c] for c in range(hash_size))
    return _bits_to_int(bits)


def image_features(path: Path) -> Dict[str, object]:
    with Image.open(path) as im:
        im.load()
        try:
            im = ImageOps.exif_transpose(im)  # honour EXIF orientation
        except Exception:  # noqa: BLE001
            pass
        if im.mode in ("RGBA", "LA", "P"):
            bg = Image.new("RGB", im.size, (255, 255, 255))
            rgba = im.convert("RGBA")
            bg.paste(rgba, mask=rgba.split()[-1])
            im = bg
        if imagehash is not None:
            ph = int(str(imagehash.phash(im)), 16)
            dh = int(str(imagehash.dhash(im)), 16)
            method = "imagehash"
        else:
            ph = phash_builtin(im)
            dh = dhash_builtin(im)
            method = "builtin"
        return {"phash": ph, "dhash": dh, "width": im.width, "height": im.height, "method": method}


class _BKTree:
    """Metric tree for Hamming-radius queries over 64-bit hashes."""

    def __init__(self) -> None:
        self.root: Optional[Tuple[int, List[int], Dict[int, "object"]]] = None

    def add(self, h: int, idx: int) -> None:
        if self.root is None:
            self.root = (h, [idx], {})
            return
        node = self.root
        while True:
            d = hamming(h, node[0])
            if d == 0:
                node[1].append(idx)
                return
            child = node[2].get(d)
            if child is None:
                node[2][d] = (h, [idx], {})
                return
            node = child  # type: ignore[assignment]

    def query(self, h: int, radius: int) -> List[int]:
        out: List[int] = []
        stack = [self.root] if self.root else []
        while stack:
            node = stack.pop()
            d = hamming(h, node[0])
            if d <= radius:
                out.extend(node[1])
            for k, child in node[2].items():
                if d - radius <= k <= d + radius:
                    stack.append(child)
        return out


class ImageSimilarityDetector(SimilarityDetector):
    name = "image"
    categories = {MediaCategory.IMAGE}

    def available(self):
        if Image is None:
            return False, "Pillow is not installed (pip install Pillow)"
        return True, ""

    def find_matches(self, records: Sequence[FileRecord]) -> List[SimilarityMatch]:
        feats: Dict[int, Dict[str, object]] = {}
        recs = list(records)
        for i, (rec, res, exc) in enumerate(bounded_map(lambda r: image_features(r.path), recs,
                                                        self.cfg.workers, self.cancel)):
            if exc is not None:
                self._issue(rec.path, f"could not decode image: {exc}")
                continue
            feats[id(rec)] = res  # type: ignore[assignment]
            self.progress.update(f"image fingerprints: {i + 1}/{len(recs)}")

        usable = [r for r in recs if id(r) in feats]
        tree = _BKTree()
        for idx, r in enumerate(usable):
            tree.add(int(feats[id(r)]["phash"]), idx)  # type: ignore[arg-type]

        probable = self.cfg.image_probable_distance
        review = self.cfg.image_review_distance
        matches: List[SimilarityMatch] = []
        for i, r in enumerate(usable):
            self.cancel.check()
            fa = feats[id(r)]
            for j in tree.query(int(fa["phash"]), review):  # type: ignore[arg-type]
                if j <= i:
                    continue
                o = usable[j]
                fb = feats[id(o)]
                dp = hamming(int(fa["phash"]), int(fb["phash"]))  # type: ignore[arg-type]
                dd = hamming(int(fa["dhash"]), int(fb["dhash"]))  # type: ignore[arg-type]
                ar_a = int(fa["width"]) / max(int(fa["height"]), 1)  # type: ignore[arg-type]
                ar_b = int(fb["width"]) / max(int(fb["height"]), 1)  # type: ignore[arg-type]
                ar_diff = abs(ar_a - ar_b) / max(ar_a, ar_b)
                worst = max(dp, dd)
                if worst <= probable and ar_diff <= 0.02:
                    cls = MatchClass.PROBABLE
                elif worst <= review and ar_diff <= 0.10:
                    cls = MatchClass.REVIEW
                else:
                    continue
                score = 1.0 - worst / 64.0
                matches.append(SimilarityMatch(r, o, cls, score, {
                    "method": f"phash+dhash({fa['method']})", "phash_distance": dp, "dhash_distance": dd,
                    "dimensions": [f"{fa['width']}x{fa['height']}", f"{fb['width']}x{fb['height']}"],
                    "aspect_ratio_diff": round(ar_diff, 4)}))
        self.progress.done()
        return matches
