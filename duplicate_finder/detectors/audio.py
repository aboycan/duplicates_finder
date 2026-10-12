"""Audio similarity.

Evidence, strongest first:

1. Chromaprint fingerprint (``fpcalc``) -> bit-similarity of the raw prints
2. FFmpeg loudness envelope (decoded PCM) -> correlation of energy curves
3. Metadata only (duration + title/artist tags) -> **review only**, never probable

Durations must agree within ``audio_duration_tolerance`` for any match, and
metadata alone can never yield more than "requires manual review".
"""

from __future__ import annotations

import math
import re
from typing import Dict, List, Optional, Sequence, Tuple

from .. import media_probe
from ..file_types import default_registry
from ..grouping import bounded_map
from ..models import FileRecord, MatchClass, MediaCategory
from .base import SimilarityDetector, SimilarityMatch


def _fp_similarity(a: List[int], b: List[int], max_offset: int = 8) -> float:
    best = 0.0
    for off in range(-max_offset, max_offset + 1):
        xs = a[max(off, 0):]
        ys = b[max(-off, 0):]
        n = min(len(xs), len(ys))
        if n < 10:
            continue
        diff = sum(bin((xs[i] ^ ys[i]) & 0xFFFFFFFF).count("1") for i in range(n))
        best = max(best, 1.0 - diff / (32.0 * n))
    return best


def _corr(xs: Sequence[float], ys: Sequence[float]) -> Optional[float]:
    n = min(len(xs), len(ys))
    if n < 20:
        return None
    xs, ys = xs[:n], ys[:n]
    mx, my = sum(xs) / n, sum(ys) / n
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if sx < 1e-6 or sy < 1e-6:
        return None  # silence / constant signal: no information
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


def _env_similarity(a: List[float], b: List[float], max_offset: int = 5) -> Optional[float]:
    best: Optional[float] = None
    for off in range(-max_offset, max_offset + 1):
        c = _corr(a[max(off, 0):], b[max(-off, 0):])
        if c is not None and (best is None or c > best):
            best = c
    return best


def _norm_tag(v: object) -> str:
    return re.sub(r"\W+", "", str(v or "")).casefold()


class AudioSimilarityDetector(SimilarityDetector):
    name = "audio"
    categories = {MediaCategory.AUDIO}

    def available(self):
        return True, ""  # degrades to metadata-only review hints

    def _features(self, rec: FileRecord) -> Dict[str, object]:
        handler = default_registry().get("audio")
        meta = handler.extract_metadata(rec.path, rec.type_info.format if rec.type_info else "") if handler else {}
        if "title" not in meta:
            probe = media_probe.ffprobe_summary(rec.path, self.cfg.external_timeout) or {}
            for k in ("title", "artist", "duration"):
                if k in probe and k not in meta:
                    meta[k] = probe[k]
        feats: Dict[str, object] = {"meta": meta, "duration": meta.get("duration")}
        fp = media_probe.chromaprint(rec.path, timeout=self.cfg.external_timeout)
        if fp:
            feats["chromaprint"] = fp
        else:
            env = media_probe.pcm_envelope(rec.path, timeout=self.cfg.external_timeout)
            if env:
                feats["envelope"] = env
        return feats

    def find_matches(self, records: Sequence[FileRecord]) -> List[SimilarityMatch]:
        recs = list(records)
        feats: Dict[int, Dict[str, object]] = {}
        for i, (rec, res, exc) in enumerate(bounded_map(self._features, recs, self.cfg.workers, self.cancel)):
            if exc is not None:
                self._issue(rec.path, f"analysis failed: {exc}")
                continue
            if res.get("duration") is None:  # type: ignore[union-attr]
                self._issue(rec.path, "duration unavailable (corrupt file or no decoder)")
                continue
            feats[id(rec)] = res  # type: ignore[assignment]
            self.progress.update(f"audio analysis: {i + 1}/{len(recs)}")

        usable = sorted((r for r in recs if id(r) in feats), key=lambda r: float(feats[id(r)]["duration"]))  # type: ignore[arg-type]
        tol = self.cfg.audio_duration_tolerance
        matches: List[SimilarityMatch] = []
        for i, a in enumerate(usable):
            self.cancel.check()
            fa = feats[id(a)]
            da = float(fa["duration"])  # type: ignore[arg-type]
            for b in usable[i + 1:]:
                fb = feats[id(b)]
                db = float(fb["duration"])  # type: ignore[arg-type]
                if db - da > tol:
                    break
                m = self._compare(a, b, fa, fb, abs(db - da))
                if m:
                    matches.append(m)
        self.progress.done()
        return matches

    def _compare(self, a: FileRecord, b: FileRecord, fa: Dict, fb: Dict, ddiff: float) -> Optional[SimilarityMatch]:
        ev = {"duration_diff": round(ddiff, 3)}
        if "chromaprint" in fa and "chromaprint" in fb:
            s = _fp_similarity(fa["chromaprint"], fb["chromaprint"])
            ev.update(method="chromaprint", similarity=round(s, 4))
            if s >= self.cfg.audio_fingerprint_probable:
                return SimilarityMatch(a, b, MatchClass.PROBABLE, s, ev)
            if s >= self.cfg.audio_fingerprint_review:
                return SimilarityMatch(a, b, MatchClass.REVIEW, s, ev)
            return None
        if "envelope" in fa and "envelope" in fb:
            s = _env_similarity(fa["envelope"], fb["envelope"])
            if s is None:
                return None
            ev.update(method="pcm-envelope", correlation=round(s, 4))
            if s >= 0.97:
                return SimilarityMatch(a, b, MatchClass.PROBABLE, s, ev)
            if s >= 0.90:
                return SimilarityMatch(a, b, MatchClass.REVIEW, s, ev)
            return None
        # Metadata only: at most a review hint, and only with matching title tags.
        ma, mb = fa["meta"], fb["meta"]
        ta, tb = _norm_tag(ma.get("title")), _norm_tag(mb.get("title"))
        if ta and ta == tb and ddiff <= 0.5 and _norm_tag(ma.get("artist")) == _norm_tag(mb.get("artist")):
            ev.update(method="metadata-only", note="metadata alone never establishes a duplicate")
            return SimilarityMatch(a, b, MatchClass.REVIEW, 0.5, ev)
        return None
