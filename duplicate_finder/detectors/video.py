"""Video similarity: duration gate + perceptual hashes of sampled frames.

Requires ``ffprobe`` and ``ffmpeg`` (stream metadata, frame extraction) and
Pillow.  Resolution, frame rate and codec differences are recorded as
evidence but do not prevent a match (transcodes and resizes are expected).
"""

from __future__ import annotations

import io
from typing import Dict, List, Optional, Sequence

from .. import media_probe
from ..grouping import bounded_map
from ..models import FileRecord, MatchClass, MediaCategory
from .base import SimilarityDetector, SimilarityMatch, hamming

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None  # type: ignore


class VideoSimilarityDetector(SimilarityDetector):
    name = "video"
    categories = {MediaCategory.VIDEO}

    def available(self):
        missing = [t for t in ("ffprobe", "ffmpeg") if not media_probe.which(t)]
        if missing:
            return False, f"{' and '.join(missing)} not found on PATH (install FFmpeg)"
        if Image is None:
            return False, "Pillow is not installed"
        return True, ""

    def _features(self, rec: FileRecord) -> Optional[Dict[str, object]]:
        from .image import dhash_builtin
        meta = media_probe.ffprobe_summary(rec.path, self.cfg.external_timeout)
        if not meta or not meta.get("duration"):
            raise ValueError("ffprobe could not read stream metadata")
        dur = float(meta["duration"])
        n = max(1, self.cfg.video_samples)
        hashes: List[int] = []
        for k in range(n):
            self.cancel.check()
            t = dur * (k + 1) / (n + 1)
            png = media_probe.extract_frame_png(rec.path, t, timeout=self.cfg.external_timeout)
            if not png:
                continue
            with Image.open(io.BytesIO(png)) as im:
                hashes.append(dhash_builtin(im))
        if len(hashes) < max(1, n // 2):
            raise ValueError("could not decode enough frames")
        return {"meta": meta, "duration": dur, "frames": hashes}

    def find_matches(self, records: Sequence[FileRecord]) -> List[SimilarityMatch]:
        recs = list(records)
        feats: Dict[int, Dict[str, object]] = {}
        # Frame extraction is CPU heavy; cap concurrency at 2 per default.
        workers = max(1, min(self.cfg.workers, 2))
        for i, (rec, res, exc) in enumerate(bounded_map(self._features, recs, workers, self.cancel)):
            if exc is not None or not res:
                self._issue(rec.path, f"analysis failed: {exc}")
                continue
            feats[id(rec)] = res
            self.progress.update(f"video analysis: {i + 1}/{len(recs)}")
        usable = sorted((r for r in recs if id(r) in feats), key=lambda r: feats[id(r)]["duration"])  # type: ignore[arg-type,return-value]
        tol = self.cfg.video_duration_tolerance
        matches: List[SimilarityMatch] = []
        for i, a in enumerate(usable):
            self.cancel.check()
            fa = feats[id(a)]
            for b in usable[i + 1:]:
                fb = feats[id(b)]
                ddiff = float(fb["duration"]) - float(fa["duration"])  # type: ignore[arg-type]
                if ddiff > tol:
                    break
                pairs = list(zip(fa["frames"], fb["frames"]))  # type: ignore[arg-type]
                if not pairs:
                    continue
                dists = [hamming(x, y) for x, y in pairs]
                mean = sum(dists) / len(dists)
                worst = max(dists)
                ma, mb = fa["meta"], fb["meta"]  # type: ignore[assignment]
                ev = {"method": "ffmpeg-frames+dhash", "mean_frame_distance": round(mean, 2),
                      "max_frame_distance": worst, "duration_diff": round(ddiff, 3),
                      "resolution": [f"{ma.get('width')}x{ma.get('height')}", f"{mb.get('width')}x{mb.get('height')}"],
                      "fps": [ma.get("fps"), mb.get("fps")]}
                if mean <= self.cfg.video_probable_distance and worst <= self.cfg.video_review_distance:
                    cls = MatchClass.PROBABLE
                elif mean <= self.cfg.video_review_distance:
                    cls = MatchClass.REVIEW
                else:
                    continue
                matches.append(SimilarityMatch(a, b, cls, 1.0 - mean / 64.0, ev))
        self.progress.done()
        return matches
