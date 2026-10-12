"""Path-safety helpers.

These helpers centralise every containment and identity check so that the
rules are implemented exactly once:

* ``is_within`` / ``assert_within`` — containment using *resolved* paths, so
  ``..`` segments and symlinks cannot escape a directory.
* ``sanitize_component`` — turns an arbitrary filename into a single safe
  path component on every supported OS.
* ``same_file`` — true when two paths refer to the same underlying file
  (symlinks, hard links, case variations on case-insensitive filesystems).

Containment checks are deliberately conservative: when in doubt they answer
"outside", which makes the caller refuse the operation.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Optional, Union

from .errors import PathOutsideAllowedRoot
from .models import StatFingerprint

PathLike = Union[str, "os.PathLike[str]"]

# Characters that are invalid in a filename on at least one supported OS.
_INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
MAX_COMPONENT_BYTES = 200  # leave head-room under the common 255-byte limit


def absolute(path: PathLike) -> Path:
    """Absolute, normalised path *without* resolving symlinks."""
    return Path(os.path.abspath(os.path.expanduser(os.fspath(path))))


def resolved(path: PathLike) -> Path:
    """Fully resolved path (symlinks followed, ``..`` removed)."""
    return Path(os.path.realpath(os.path.expanduser(os.fspath(path))))


def _norm(p: Path) -> str:
    # normcase lower-cases on Windows; elsewhere it is the identity.  A
    # case-sensitive comparison on a case-insensitive filesystem can only
    # produce "outside" for a path that is really inside, which is the safe
    # failure direction.
    return os.path.normcase(str(p))


def is_within(child: PathLike, parent: PathLike) -> bool:
    """True if *child* resolves to *parent* or somewhere beneath it."""
    c = _norm(resolved(child))
    p = _norm(resolved(parent))
    try:
        return os.path.commonpath([c, p]) == p
    except ValueError:  # different drives on Windows
        return False


def assert_within(child: PathLike, parent: PathLike, what: str = "path") -> None:
    if not is_within(child, parent):
        raise PathOutsideAllowedRoot(
            f"{what} {os.fspath(child)!r} resolves outside {os.fspath(parent)!r}"
        )


def same_file(a: PathLike, b: PathLike) -> bool:
    """True if both paths exist and refer to the same file (or hard link)."""
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def fingerprint(path: PathLike, follow_symlinks: bool = False) -> StatFingerprint:
    return StatFingerprint.from_stat(os.stat(path, follow_symlinks=follow_symlinks))


def is_regular_file(path: PathLike) -> bool:
    """Regular file test that does **not** follow symlinks."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def sanitize_component(name: str, fallback: str = "file") -> str:
    """Return *name* as a single filename that is valid on Windows, macOS and Linux.

    The result never contains a path separator and is never ``.``/``..``,
    so it cannot be used for path traversal.
    """
    name = unicodedata.normalize("NFC", name)
    name = _INVALID_CHARS.sub("_", name)
    name = name.strip().rstrip(". ")
    if name in {"", ".", ".."}:
        name = fallback
    stem, dot, ext = name.partition(".")
    if stem.upper() in _WINDOWS_RESERVED:
        name = f"_{name}"
    # Truncate by encoded length while keeping the extension.
    encoded = name.encode("utf-8")
    if len(encoded) > MAX_COMPONENT_BYTES:
        base, ext = os.path.splitext(name)
        ext = ext[:20]
        budget = MAX_COMPONENT_BYTES - len(ext.encode("utf-8"))
        base = base.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
        name = (base or fallback) + ext
    return name


def safe_relative(rel: PathLike) -> Path:
    """Sanitise every component of a relative path.

    Absolute paths, drive letters and ``..`` are neutralised so the result can
    only ever be joined *beneath* a base directory.
    """
    parts = []
    for part in Path(os.fspath(rel)).parts:
        if part in ("", ".", os.sep, "/", "\\"):
            continue
        if part == "..":
            parts.append("__")
            continue
        # Drive or UNC anchors such as "C:\\" or "\\\\server\\share\\".
        if part.endswith((":", ":\\", ":/")) or part.startswith(("\\\\", "//")):
            part = part.replace(":", "").strip("\\/") or "drive"
        parts.append(sanitize_component(part))
    return Path(*parts) if parts else Path("file")


def check_destination_root(destination: Path, roots: "list[Path]") -> Optional[str]:
    """Return a warning string if the destination overlaps a scan root.

    A destination *inside* a scan root is permitted (it is excluded from
    traversal), but a scan root inside the destination is refused by the
    caller because files would be moved within their own tree.
    """
    for root in roots:
        if is_within(root, destination):
            return f"scan root {root} is inside the destination {destination}"
    return None
