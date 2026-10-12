"""Optional, type-specific similarity detectors.

Register an additional detector with :func:`register_detector`; it will be
run in ``--mode similarity`` / ``--mode all`` for records in its categories.
"""

from __future__ import annotations

from typing import List, Type

from .audio import AudioSimilarityDetector
from .base import SimilarityDetector, SimilarityMatch, build_groups, hamming
from .image import ImageSimilarityDetector
from .video import VideoSimilarityDetector

_DETECTORS: List[Type[SimilarityDetector]] = [
    ImageSimilarityDetector,
    AudioSimilarityDetector,
    VideoSimilarityDetector,
]


def register_detector(cls: Type[SimilarityDetector]) -> None:
    if not issubclass(cls, SimilarityDetector):
        raise TypeError("detector must subclass SimilarityDetector")
    if cls not in _DETECTORS:
        _DETECTORS.append(cls)


def detector_classes() -> List[Type[SimilarityDetector]]:
    return list(_DETECTORS)


__all__ = ["SimilarityDetector", "SimilarityMatch", "build_groups", "hamming", "register_detector",
           "detector_classes", "ImageSimilarityDetector", "AudioSimilarityDetector", "VideoSimilarityDetector"]
