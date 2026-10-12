"""File-type detection and the handler registry.

Detection is signature-first: the first bytes of every file are matched
against known magic numbers.  The extension is used only to

* disambiguate container families where the signature alone cannot tell the
  formats apart (ISO-BMFF ``.mp4``/``.m4a``/``.mov``, ASF ``.wmv``/``.wma``,
  TIFF-based RAW formats), and
* fall back when no signature matches (reported as ``detected_by="extension"``).

A mismatch between signature and extension is reported, never silently trusted.

Extending
---------
Subclass :class:`FileTypeHandler`, describe the formats it owns and register an
instance::

    from duplicate_finder.file_types import FileTypeHandler, FormatSpec, default_registry
    from duplicate_finder.models import MediaCategory

    class SvgHandler(FileTypeHandler):
        name = "svg"
        formats = {"svg": FormatSpec(MediaCategory.IMAGE, "image/svg+xml", (".svg",))}

        def identify(self, header, extension):
            head = header[:512].lstrip().lower()
            return "svg" if head.startswith(b"<svg") or b"<svg" in head else None

    default_registry().register(SvgHandler())

Handlers may also be loaded by module name from the configuration
(``plugins = ["my_package.my_handlers"]``); such a module must expose
``register(registry)``.
"""

from __future__ import annotations

import importlib
import os
import threading
from abc import ABC
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import FileTypeInfo, MediaCategory

HEADER_BYTES = 4096


@dataclass(frozen=True)
class FormatSpec:
    category: MediaCategory
    mime: str
    extensions: Tuple[str, ...]
    family: str = ""   # formats sharing a container/signature share a family


class FileTypeHandler(ABC):
    """Base class for file-type handlers.

    Required: ``name`` and ``formats``.  Everything else is optional.
    """

    name: str = ""
    formats: Dict[str, FormatSpec] = {}
    #: extra columns this handler contributes to reports (keys of extract_metadata)
    report_fields: Tuple[str, ...] = ()
    #: lower number = consulted earlier for signature matching
    priority: int = 100

    def identify(self, header: bytes, extension: str) -> Optional[str]:
        """Return a format name from ``formats`` if the signature matches."""
        return None

    def extract_metadata(self, path: Path, fmt: str) -> Dict[str, Any]:
        """Optional metadata (dimensions, duration ...).  Must not raise."""
        return {}

    def validate(self, path: Path, fmt: str) -> Optional[str]:
        """Optional deep validation.  Return an error message if corrupt."""
        return None


# --------------------------------------------------------------------------- helpers

def _iso_bmff_brands(header: bytes) -> List[bytes]:
    """Major + compatible brands of an ISO base-media ``ftyp`` box."""
    if len(header) < 12 or header[4:8] != b"ftyp":
        return []
    size = int.from_bytes(header[0:4], "big")
    size = min(max(size, 16), len(header))
    brands = [header[8:12]]
    for off in range(16, size - 3, 4):
        brands.append(header[off:off + 4])
    return brands


def _riff_type(header: bytes) -> Optional[bytes]:
    if len(header) >= 12 and header[0:4] in (b"RIFF", b"RIFX"):
        return header[8:12]
    return None


def _ebml_doctype(header: bytes) -> Optional[str]:
    if not header.startswith(b"\x1a\x45\xdf\xa3"):
        return None
    idx = header.find(b"\x42\x82")  # DocType element id
    if idx == -1:
        return "matroska"
    size_byte = header[idx + 2] if idx + 2 < len(header) else 0
    length = size_byte & 0x7F if size_byte & 0x80 else 8
    return header[idx + 3: idx + 3 + length].decode("ascii", "ignore").strip("\x00") or "matroska"


# --------------------------------------------------------------------------- built-ins

_TIFF_RAW_EXT = {".cr2": "cr2", ".nef": "nef", ".nrw": "nef", ".arw": "arw", ".srf": "arw",
                 ".sr2": "arw", ".dng": "dng", ".pef": "pef", ".srw": "srw", ".3fr": "3fr",
                 ".erf": "erf", ".kdc": "kdc", ".mos": "mos", ".iiq": "iiq"}


class ImageHandler(FileTypeHandler):
    name = "image"
    priority = 10
    report_fields = ("width", "height")
    formats = {
        "jpeg": FormatSpec(MediaCategory.IMAGE, "image/jpeg", (".jpg", ".jpeg", ".jpe", ".jfif")),
        "png": FormatSpec(MediaCategory.IMAGE, "image/png", (".png",)),
        "gif": FormatSpec(MediaCategory.IMAGE, "image/gif", (".gif",)),
        "bmp": FormatSpec(MediaCategory.IMAGE, "image/bmp", (".bmp", ".dib")),
        "tiff": FormatSpec(MediaCategory.IMAGE, "image/tiff", (".tif", ".tiff"), "tiff"),
        "webp": FormatSpec(MediaCategory.IMAGE, "image/webp", (".webp",)),
        "heic": FormatSpec(MediaCategory.IMAGE, "image/heic", (".heic", ".heics"), "heif"),
        "heif": FormatSpec(MediaCategory.IMAGE, "image/heif", (".heif", ".hif"), "heif"),
        "avif": FormatSpec(MediaCategory.IMAGE, "image/avif", (".avif",)),
        # RAW formats.  TIFF-based ones share the tiff family and are told apart
        # by extension; a few have their own magic numbers.
        **{fmt: FormatSpec(MediaCategory.IMAGE, f"image/x-{fmt}", tuple(
            e for e, f in _TIFF_RAW_EXT.items() if f == fmt), "tiff")
           for fmt in sorted(set(_TIFF_RAW_EXT.values()))},
        "cr3": FormatSpec(MediaCategory.IMAGE, "image/x-canon-cr3", (".cr3",)),
        "raf": FormatSpec(MediaCategory.IMAGE, "image/x-fuji-raf", (".raf",)),
        "orf": FormatSpec(MediaCategory.IMAGE, "image/x-olympus-orf", (".orf",)),
        "rw2": FormatSpec(MediaCategory.IMAGE, "image/x-panasonic-rw2", (".rw2", ".raw")),
    }

    def identify(self, header: bytes, extension: str) -> Optional[str]:
        h = header
        if h.startswith(b"\xff\xd8\xff"):
            return "jpeg"
        if h.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if h[:6] in (b"GIF87a", b"GIF89a"):
            return "gif"
        if h.startswith(b"BM") and len(h) >= 26 and int.from_bytes(h[14:18], "little") in (12, 40, 52, 56, 64, 108, 124):
            return "bmp"
        if _riff_type(h) == b"WEBP":
            return "webp"
        if h.startswith(b"FUJIFILMCCD-RAW"):
            return "raf"
        if h[:4] in (b"IIRO", b"IIRS", b"MMOR"):
            return "orf"
        if h[:4] == b"IIU\x00":
            return "rw2"
        if h[:4] in (b"II*\x00", b"MM\x00*"):
            if h[8:10] == b"CR":
                return "cr2"
            return "tiff"
        brands = _iso_bmff_brands(h)
        if brands:
            if brands[0] == b"crx ":
                return "cr3"
            if brands[0] in (b"avif", b"avis"):
                return "avif"
            if brands[0] in (b"heic", b"heix", b"hevc", b"hevx", b"heim", b"heis"):
                return "heic"
            if brands[0] in (b"mif1", b"msf1"):
                if b"avif" in brands or b"avis" in brands:
                    return "avif"
                if any(b in brands for b in (b"heic", b"heix")):
                    return "heic"
                return "heif"
        return None

    def extract_metadata(self, path: Path, fmt: str) -> Dict[str, Any]:
        try:
            from PIL import Image  # optional
        except ImportError:
            return {}
        try:
            with Image.open(path) as im:
                return {"width": im.width, "height": im.height, "mode": im.mode}
        except Exception:  # noqa: BLE001 - metadata is best-effort
            return {}

    def validate(self, path: Path, fmt: str) -> Optional[str]:
        try:
            from PIL import Image
        except ImportError:
            return None
        if fmt in _TIFF_RAW_EXT.values() or fmt in ("cr3", "raf", "orf", "rw2", "heic", "heif", "avif"):
            return None  # Pillow cannot decode these without plugins
        try:
            with Image.open(path) as im:
                im.verify()
        except Exception as exc:  # noqa: BLE001
            return f"image failed to decode: {exc}"
        return None


_MP4_VIDEO_BRANDS = {b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6", b"mp41", b"mp42",
                     b"avc1", b"dash", b"mmp4", b"MSNV", b"XAVC", b"NDAS", b"f4v "}


class VideoHandler(FileTypeHandler):
    name = "video"
    priority = 20
    report_fields = ("duration", "width", "height")
    formats = {
        "mp4": FormatSpec(MediaCategory.VIDEO, "video/mp4", (".mp4", ".f4v"), "isobmff"),
        "m4v": FormatSpec(MediaCategory.VIDEO, "video/x-m4v", (".m4v",), "isobmff"),
        "mov": FormatSpec(MediaCategory.VIDEO, "video/quicktime", (".mov", ".qt"), "isobmff"),
        "3gp": FormatSpec(MediaCategory.VIDEO, "video/3gpp", (".3gp", ".3g2", ".3gpp"), "isobmff"),
        "mkv": FormatSpec(MediaCategory.VIDEO, "video/x-matroska", (".mkv",), "ebml"),
        "webm": FormatSpec(MediaCategory.VIDEO, "video/webm", (".webm",), "ebml"),
        "avi": FormatSpec(MediaCategory.VIDEO, "video/x-msvideo", (".avi",)),
        "wmv": FormatSpec(MediaCategory.VIDEO, "video/x-ms-wmv", (".wmv", ".asf"), "asf"),
        "flv": FormatSpec(MediaCategory.VIDEO, "video/x-flv", (".flv",)),
        "mpeg": FormatSpec(MediaCategory.VIDEO, "video/mpeg", (".mpg", ".mpeg", ".mpe", ".vob", ".m2v"), "mpeg"),
        "mpegts": FormatSpec(MediaCategory.VIDEO, "video/mp2t", (".ts", ".mts", ".m2ts"), "mpeg"),
    }

    def identify(self, header: bytes, extension: str) -> Optional[str]:
        h = header
        brands = _iso_bmff_brands(h)
        if brands:
            major = brands[0]
            if major == b"qt  ":
                return "mov"
            if major in (b"M4V ", b"M4VH", b"M4VP"):
                return "m4v"
            if major.startswith((b"3gp", b"3g2")):
                return "3gp"
            if major in _MP4_VIDEO_BRANDS:
                return "mp4"
            return None
        # Old QuickTime files may start without an ``ftyp`` box.
        if h[4:8] in (b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot") and extension in (".mov", ".qt", ".mp4", ".m4v"):
            return "mov"
        doctype = _ebml_doctype(h)
        if doctype:
            return "webm" if doctype == "webm" else "mkv"
        if _riff_type(h) == b"AVI ":
            return "avi"
        if h.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"):
            return "wmv"
        if h.startswith(b"FLV\x01"):
            return "flv"
        if h.startswith(b"\x00\x00\x01\xba") or h.startswith(b"\x00\x00\x01\xb3"):
            return "mpeg"
        if len(h) > 376 and h[0] == 0x47 and h[188] == 0x47 and h[376] == 0x47:
            return "mpegts"
        if len(h) > 196 and h[4] == 0x47 and h[196] == 0x47:  # 192-byte M2TS packets
            return "mpegts"
        return None

    def extract_metadata(self, path: Path, fmt: str) -> Dict[str, Any]:
        from .media_probe import ffprobe_summary
        return ffprobe_summary(path) or {}


class AudioHandler(FileTypeHandler):
    name = "audio"
    priority = 30
    report_fields = ("duration", "bitrate", "codec")
    formats = {
        "mp3": FormatSpec(MediaCategory.AUDIO, "audio/mpeg", (".mp3",)),
        "wav": FormatSpec(MediaCategory.AUDIO, "audio/wav", (".wav", ".wave")),
        "flac": FormatSpec(MediaCategory.AUDIO, "audio/flac", (".flac",)),
        "aac": FormatSpec(MediaCategory.AUDIO, "audio/aac", (".aac",)),
        # ALAC lives in an M4A container; the codec is reported by metadata.
        "m4a": FormatSpec(MediaCategory.AUDIO, "audio/mp4", (".m4a", ".m4b", ".m4p", ".alac"), "isobmff"),
        "ogg": FormatSpec(MediaCategory.AUDIO, "audio/ogg", (".ogg", ".oga"), "ogg"),
        "opus": FormatSpec(MediaCategory.AUDIO, "audio/opus", (".opus",), "ogg"),
        "wma": FormatSpec(MediaCategory.AUDIO, "audio/x-ms-wma", (".wma",), "asf"),
        "aiff": FormatSpec(MediaCategory.AUDIO, "audio/aiff", (".aiff", ".aif", ".aifc")),
        "mka": FormatSpec(MediaCategory.AUDIO, "audio/x-matroska", (".mka",), "ebml"),
    }

    def identify(self, header: bytes, extension: str) -> Optional[str]:
        h = header
        brands = _iso_bmff_brands(h)
        if brands and brands[0] in (b"M4A ", b"M4B ", b"M4P ", b"F4A "):
            return "m4a"
        if _riff_type(h) == b"WAVE":
            return "wav"
        if h.startswith(b"fLaC"):
            return "flac"
        if h.startswith(b"OggS"):
            return "opus" if b"OpusHead" in h[:512] else "ogg"
        if h[:4] == b"FORM" and h[8:12] in (b"AIFF", b"AIFC"):
            return "aiff"
        if h.startswith(b"ID3"):
            # ID3 is also used in front of AAC streams; look at the frame after it.
            size = ((h[6] & 0x7F) << 21) | ((h[7] & 0x7F) << 14) | ((h[8] & 0x7F) << 7) | (h[9] & 0x7F) if len(h) >= 10 else 0
            nxt = h[10 + size: 12 + size]
            if len(nxt) == 2 and nxt[0] == 0xFF and (nxt[1] & 0xF6) == 0xF0:
                return "aac"
            return "mp3"
        if len(h) >= 2 and h[0] == 0xFF:
            if (h[1] & 0xF6) == 0xF0:   # ADTS: sync + layer 00
                return "aac"
            if (h[1] & 0xE0) == 0xE0 and (h[1] & 0x06) != 0:  # MPEG audio layer I-III
                return "mp3"
        return None

    def extract_metadata(self, path: Path, fmt: str) -> Dict[str, Any]:
        try:
            import mutagen  # optional
        except ImportError:
            mutagen = None
        if mutagen is not None:
            try:
                mf = mutagen.File(path)
                if mf is not None and getattr(mf, "info", None) is not None:
                    info = mf.info
                    return {
                        "duration": round(float(getattr(info, "length", 0.0) or 0.0), 3),
                        "bitrate": getattr(info, "bitrate", None),
                        "sample_rate": getattr(info, "sample_rate", None),
                        "channels": getattr(info, "channels", None),
                        "codec": getattr(info, "codec", None) or type(info).__name__,
                    }
            except Exception:  # noqa: BLE001
                pass
        from .media_probe import ffprobe_summary
        return ffprobe_summary(path) or {}


class HandlerRegistry:
    """Ordered, thread-safe collection of :class:`FileTypeHandler` objects."""

    def __init__(self, handlers: Iterable[FileTypeHandler] = ()):  # noqa: D401
        self._lock = threading.Lock()
        self._handlers: List[FileTypeHandler] = []
        self._ext_index: Dict[str, Tuple[FileTypeHandler, str]] = {}
        for h in handlers:
            self.register(h)

    # -- registration -------------------------------------------------------
    def register(self, handler: FileTypeHandler) -> None:
        if not handler.name:
            raise ValueError("handler must define a non-empty name")
        if not handler.formats:
            raise ValueError(f"handler {handler.name!r} defines no formats")
        with self._lock:
            self._handlers = [h for h in self._handlers if h.name != handler.name]
            self._handlers.append(handler)
            self._handlers.sort(key=lambda h: h.priority)
            self._rebuild_index()

    def _rebuild_index(self) -> None:
        idx: Dict[str, Tuple[FileTypeHandler, str]] = {}
        # Earlier (higher-priority) handlers win extension conflicts.
        for h in reversed(self._handlers):
            for fmt, spec in h.formats.items():
                for ext in spec.extensions:
                    idx[ext.lower()] = (h, fmt)
        self._ext_index = idx

    def load_plugin_modules(self, modules: Sequence[str]) -> None:
        for mod_name in modules:
            mod = importlib.import_module(mod_name)
            register = getattr(mod, "register", None)
            if not callable(register):
                raise ValueError(f"plugin module {mod_name!r} has no register(registry) function")
            register(self)

    def load_entry_points(self, group: str = "duplicate_finder.handlers") -> None:
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover
            return
        try:
            eps = entry_points(group=group)  # type: ignore[call-arg]
        except TypeError:  # pragma: no cover - Python 3.9
            eps = entry_points().get(group, [])  # type: ignore[attr-defined]
        for ep in eps:
            obj = ep.load()
            if isinstance(obj, FileTypeHandler):
                self.register(obj)
            elif callable(obj):
                obj(self)

    # -- lookup ---------------------------------------------------------------
    @property
    def handlers(self) -> List[FileTypeHandler]:
        return list(self._handlers)

    def get(self, name: str) -> Optional[FileTypeHandler]:
        for h in self._handlers:
            if h.name == name:
                return h
        return None

    def spec(self, handler_name: str, fmt: str) -> Optional[FormatSpec]:
        h = self.get(handler_name)
        return h.formats.get(fmt) if h else None

    def by_extension(self, ext: str) -> Optional[Tuple[FileTypeHandler, str]]:
        return self._ext_index.get(ext.lower())

    def detect_header(self, header: bytes, extension: str) -> FileTypeInfo:
        ext = extension.lower()
        ext_hit = self.by_extension(ext)
        sig_hit: Optional[Tuple[FileTypeHandler, str]] = None
        for h in self._handlers:
            try:
                fmt = h.identify(header, ext)
            except Exception:  # noqa: BLE001 - a broken plugin must not kill the scan
                fmt = None
            if fmt and fmt in h.formats:
                sig_hit = (h, fmt)
                break

        if sig_hit:
            handler, fmt = sig_hit
            spec = handler.formats[fmt]
            mismatch = False
            if ext_hit and ext_hit != sig_hit:
                e_handler, e_fmt = ext_hit
                e_spec = e_handler.formats[e_fmt]
                if spec.family and spec.family == e_spec.family:
                    # Same container family: the extension is the better hint
                    # (e.g. an ISO-BMFF ``isom`` file named ``.m4a``).
                    handler, fmt, spec = e_handler, e_fmt, e_spec
                else:
                    mismatch = True
            elif ext and not ext_hit:
                mismatch = False  # unknown extension: nothing to contradict
            return FileTypeInfo(spec.category, fmt, spec.mime, "signature", ext, mismatch, handler.name)

        if ext_hit:
            handler, fmt = ext_hit
            spec = handler.formats[fmt]
            return FileTypeInfo(spec.category, fmt, spec.mime, "extension", ext, False, handler.name)
        return FileTypeInfo(MediaCategory.OTHER, "unknown", "application/octet-stream", "none", ext, False, "")

    def detect(self, path: Path) -> FileTypeInfo:
        """Read the header of *path* and detect its type.  Raises ``OSError``."""
        with open(path, "rb") as fh:
            header = fh.read(HEADER_BYTES)
        return self.detect_header(header, os.path.splitext(path.name)[1])


_default: Optional[HandlerRegistry] = None
_default_lock = threading.Lock()


def builtin_handlers() -> List[FileTypeHandler]:
    return [ImageHandler(), VideoHandler(), AudioHandler()]


def default_registry() -> HandlerRegistry:
    global _default
    with _default_lock:
        if _default is None:
            _default = HandlerRegistry(builtin_handlers())
        return _default


def new_registry() -> HandlerRegistry:
    """A fresh registry containing only the built-in handlers."""
    return HandlerRegistry(builtin_handlers())
