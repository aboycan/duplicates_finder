"""Optional FFmpeg / Chromaprint integration.

All external programs are invoked with argument arrays (never a shell), with a
timeout, and with the file path passed after ``--``-style separation where the
tool supports it.  Every function returns ``None`` when the tool is missing or
fails; callers treat that as "capability unavailable", never as evidence.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_TIMEOUT = 60.0


@lru_cache(maxsize=None)
def which(tool: str) -> Optional[str]:
    env_override = os.environ.get(f"DUPFINDER_{tool.upper()}")
    if env_override:
        return env_override if os.path.isfile(env_override) else None
    return shutil.which(tool)


def _safe_input(path: Path) -> str:
    # ffmpeg/ffprobe treat arguments beginning with "-" as options and strings
    # with "proto:" as protocols.  An absolute path avoids both; "file:" makes
    # the protocol explicit.
    return "file:" + str(Path(path).absolute())


def _run(args: List[str], timeout: float) -> Optional[subprocess.CompletedProcess]:
    try:
        return subprocess.run(  # noqa: S603 - argument array, no shell
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def ffprobe_json(path: Path, timeout: float = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    exe = which("ffprobe")
    if not exe:
        return None
    proc = _run([exe, "-v", "error", "-print_format", "json", "-show_format", "-show_streams",
                 _safe_input(path)], timeout)
    if proc is None or proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout.decode("utf-8", "replace"))
    except ValueError:
        return None


def ffprobe_summary(path: Path, timeout: float = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    data = ffprobe_json(path, timeout)
    if not data:
        return None
    fmt = data.get("format", {}) or {}
    out: Dict[str, Any] = {}
    try:
        out["duration"] = round(float(fmt.get("duration")), 3)
    except (TypeError, ValueError):
        pass
    try:
        out["bitrate"] = int(fmt.get("bit_rate"))
    except (TypeError, ValueError):
        pass
    tags = {str(k).lower(): v for k, v in (fmt.get("tags") or {}).items()}
    for key in ("title", "artist", "album"):
        if tags.get(key):
            out[key] = str(tags[key])
    for stream in data.get("streams", []) or []:
        kind = stream.get("codec_type")
        if kind == "video" and "width" not in out and stream.get("disposition", {}).get("attached_pic") != 1:
            out["width"] = stream.get("width")
            out["height"] = stream.get("height")
            out["video_codec"] = stream.get("codec_name")
            rate = stream.get("avg_frame_rate") or stream.get("r_frame_rate") or "0/1"
            try:
                num, den = rate.split("/")
                out["fps"] = round(float(num) / float(den), 3) if float(den) else None
            except (ValueError, ZeroDivisionError):
                out["fps"] = None
        elif kind == "audio" and "codec" not in out:
            out["codec"] = stream.get("codec_name")
            out["sample_rate"] = stream.get("sample_rate")
            out["channels"] = stream.get("channels")
    return out


def extract_frame_png(path: Path, at_seconds: float, width: int = 64,
                      timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
    """Return a single frame as PNG bytes (scaled), or ``None``."""
    exe = which("ffmpeg")
    if not exe:
        return None
    proc = _run([exe, "-v", "error", "-nostdin", "-ss", f"{max(at_seconds, 0):.3f}", "-i", _safe_input(path),
                 "-frames:v", "1", "-vf", f"scale={width}:-2", "-f", "image2pipe", "-vcodec", "png", "pipe:1"],
                timeout)
    if proc is None or proc.returncode != 0 or not proc.stdout:
        return None
    return proc.stdout


def pcm_envelope(path: Path, seconds: float = 120.0, rate: int = 8000, frame_ms: int = 100,
                 timeout: float = DEFAULT_TIMEOUT) -> Optional[List[float]]:
    """Loudness envelope (log RMS per frame) of the first *seconds* of audio.

    A transcoding-robust fallback fingerprint when Chromaprint is unavailable:
    bitrate, codec and container changes barely affect the energy envelope.
    """
    exe = which("ffmpeg")
    if not exe:
        return None
    proc = _run([exe, "-v", "error", "-nostdin", "-i", _safe_input(path), "-t", f"{seconds:.1f}",
                 "-vn", "-ac", "1", "-ar", str(rate), "-f", "s16le", "-acodec", "pcm_s16le", "pipe:1"], timeout)
    if proc is None or proc.returncode != 0 or len(proc.stdout) < 2 * rate // 2:
        return None
    import array
    import math
    import sys as _sys
    samples = array.array("h")
    data = proc.stdout[: len(proc.stdout) - (len(proc.stdout) % 2)]
    samples.frombytes(data)
    if _sys.byteorder == "big":
        samples.byteswap()
    step = max(1, rate * frame_ms // 1000)
    env = []
    for i in range(0, len(samples) - step + 1, step):
        block = samples[i:i + step]
        energy = sum(s * s for s in block) / step
        env.append(math.log10(energy + 1.0))
    return env


def chromaprint(path: Path, length: int = 120, timeout: float = DEFAULT_TIMEOUT) -> Optional[List[int]]:
    """Raw Chromaprint fingerprint via ``fpcalc``; ``None`` if unavailable."""
    exe = which("fpcalc")
    if not exe:
        return None
    proc = _run([exe, "-raw", "-json", "-length", str(int(length)), str(Path(path).absolute())], timeout)
    if proc is None or proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout.decode("utf-8", "replace"))
        fp = data.get("fingerprint")
        return [int(x) for x in fp] if isinstance(fp, list) else None
    except (ValueError, TypeError):
        return None
