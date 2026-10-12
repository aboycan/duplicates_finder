"""Settings, defaults, config-file loading and extension registration.

Precedence: built-in defaults < config file (TOML or JSON) < command line.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import ConfigError
from .models import MediaCategory

MODES = ("exact", "similarity", "all")
ACTIONS = ("dry-run", "report", "interactive", "auto")
LAYOUTS = ("category", "flat", "mirror")
SYMLINK_POLICIES = ("skip", "follow-within-roots")
VERIFY_LEVELS = ("sha256", "bytes")
KEEP_CRITERIA = ("prefer-paths", "root-order", "oldest", "newest", "shortest-path", "longest-name",
                 "shortest-name", "path")

DEFAULT_EXCLUDE_DIRS = [
    ".git", ".hg", ".svn", "__pycache__", "node_modules",
    "$RECYCLE.BIN", "System Volume Information", ".Trash", ".Trashes", ".Trash-*",
    ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100",
]
DEFAULT_EXCLUDE_FILES = ["Thumbs.db", "desktop.ini", ".DS_Store", "*.dfpart", "._*"]


def default_state_dir() -> Path:
    """Per-user directory for the database, journal and reports."""
    override = os.environ.get("DUPFINDER_STATE_DIR")
    if override:
        return Path(override).expanduser()
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
        return Path(base) / "duplicate_finder"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "duplicate_finder"
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "duplicate_finder"


@dataclass
class Config:
    roots: List[Path] = field(default_factory=list)
    destination: Optional[Path] = None
    state_dir: Path = field(default_factory=default_state_dir)
    report_dir: Optional[Path] = None

    mode: str = "exact"
    action: str = "dry-run"
    layout: str = "category"
    category_dirs: Dict[str, str] = field(default_factory=lambda: {
        "image": "Images", "video": "Videos", "audio": "Audio", "other": "Other"})
    categories: List[str] = field(default_factory=lambda: ["image", "video", "audio", "other"])

    exclude_dirs: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_DIRS))
    exclude_files: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_FILES))
    min_size: int = 0
    max_size: Optional[int] = None
    symlink_policy: str = "skip"
    hardlinks_as_duplicates: bool = False

    verify: str = "sha256"
    chunk_size: int = 1024 * 1024
    workers: int = 4
    use_cache: bool = True
    stability_seconds: float = 0.0
    validate_media: bool = False

    keep: List[str] = field(default_factory=lambda: ["prefer-paths", "root-order", "oldest", "shortest-path", "path"])
    prefer_paths: List[Path] = field(default_factory=list)

    # similarity
    image_probable_distance: int = 4
    image_review_distance: int = 10
    audio_duration_tolerance: float = 1.0
    audio_fingerprint_probable: float = 0.92
    audio_fingerprint_review: float = 0.80
    video_samples: int = 5
    video_duration_tolerance: float = 1.5
    video_probable_distance: float = 6.0
    video_review_distance: float = 12.0
    external_timeout: float = 60.0

    report_formats: List[str] = field(default_factory=lambda: ["json", "csv", "text"])
    redact_paths: bool = False
    plugins: List[str] = field(default_factory=list)
    progress: bool = True
    assume_yes: bool = False

    # ------------------------------------------------------------------ derived
    @property
    def db_path(self) -> Path:
        return self.state_dir / "state.sqlite3"

    @property
    def journal_path(self) -> Path:
        return self.state_dir / "journal.jsonl"

    @property
    def effective_report_dir(self) -> Path:
        return self.report_dir or (self.state_dir / "reports")

    def effective_destination(self) -> Path:
        if self.destination is not None:
            return self.destination
        if not self.roots:
            raise ConfigError("no destination and no scan roots")
        first = Path(os.path.abspath(self.roots[0]))
        parent = first.parent if first.parent != first else first
        return parent / "Duplicates"

    # ------------------------------------------------------------------ validation
    def validate(self) -> None:
        def _choice(name: str, value: str, allowed: tuple) -> None:
            if value not in allowed:
                raise ConfigError(f"{name} must be one of {', '.join(allowed)} (got {value!r})")

        _choice("mode", self.mode, MODES)
        _choice("action", self.action, ACTIONS)
        _choice("layout", self.layout, LAYOUTS)
        _choice("symlink_policy", self.symlink_policy, SYMLINK_POLICIES)
        _choice("verify", self.verify, VERIFY_LEVELS)
        for k in self.keep:
            _choice("keep criterion", k, KEEP_CRITERIA)
        valid_cats = {c.value for c in MediaCategory}
        for c in self.categories:
            _choice("category", c, tuple(sorted(valid_cats)))
        for c in valid_cats:
            name = self.category_dirs.get(c)
            if not name or re.search(r"[\\/]|^\.\.?$", name):
                raise ConfigError(f"category_dirs[{c!r}] must be a single folder name")
        if self.chunk_size < 4096:
            raise ConfigError("chunk_size must be at least 4096 bytes")
        if not 1 <= self.workers <= 64:
            raise ConfigError("workers must be between 1 and 64")
        if self.min_size < 0 or (self.max_size is not None and self.max_size < self.min_size):
            raise ConfigError("invalid min_size/max_size")
        if self.image_probable_distance > self.image_review_distance:
            raise ConfigError("image_probable_distance must not exceed image_review_distance")
        for fmt in self.report_formats:
            _choice("report format", fmt, ("json", "csv", "text"))


# ---------------------------------------------------------------------- loading

def _load_toml(text: str) -> Dict[str, Any]:
    try:
        import tomllib  # Python 3.11+
        return tomllib.loads(text)
    except ImportError:
        pass
    try:
        import tomli  # type: ignore
        return tomli.loads(text)
    except ImportError:
        return _mini_toml(text)


_KEY_RE = re.compile(r"^([A-Za-z0-9_\-]+)\s*=\s*(.+)$")


def _mini_toml(text: str) -> Dict[str, Any]:
    """Minimal TOML subset parser (tables, strings, numbers, bools, flat arrays).

    Used only on Python < 3.11 when ``tomli`` is not installed.  It is enough
    for the sample configuration shipped with the project.
    """
    root: Dict[str, Any] = {}
    current = root
    pending_key: Optional[str] = None
    pending_val = ""
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if pending_key is not None:
            pending_val += " " + line
            if pending_val.count("[") <= pending_val.count("]"):
                current[pending_key] = _toml_value(pending_val, lineno)
                pending_key = None
            continue
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = root
            for part in line[1:-1].strip().split("."):
                current = current.setdefault(part.strip(), {})
            continue
        m = _KEY_RE.match(line)
        if not m:
            raise ConfigError(f"config line {lineno}: cannot parse {raw!r}")
        key, val = m.group(1), m.group(2).strip()
        if val.startswith("[") and val.count("[") > val.count("]"):
            pending_key, pending_val = key, val
            continue
        current[key] = _toml_value(val, lineno)
    if pending_key is not None:
        raise ConfigError("config: unterminated array")
    return root


def _strip_comment(line: str) -> str:
    out, quote = [], None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def _toml_value(val: str, lineno: int) -> Any:
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        items, buf, quote = [], "", None
        for ch in inner:
            if quote:
                buf += ch
                if ch == quote:
                    quote = None
            elif ch in ("'", '"'):
                quote = ch
                buf += ch
            elif ch == ",":
                if buf.strip():
                    items.append(_toml_value(buf, lineno))
                buf = ""
            else:
                buf += ch
        if buf.strip():
            items.append(_toml_value(buf, lineno))
        return items
    if val.startswith("'") and val.endswith("'") and len(val) >= 2:
        return val[1:-1]
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        return json.loads(val)
    if val in ("true", "false"):
        return val == "true"
    try:
        return int(val.replace("_", ""))
    except ValueError:
        pass
    try:
        return float(val.replace("_", ""))
    except ValueError:
        raise ConfigError(f"config line {lineno}: unsupported value {val!r}") from None


_PATH_FIELDS = {"destination", "state_dir", "report_dir"}
_PATH_LIST_FIELDS = {"roots", "prefer_paths"}


def load_config_file(path: Path) -> Dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    if str(path).lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    else:
        try:
            data = _load_toml(text)
        except ConfigError:
            raise
        except Exception as exc:  # noqa: BLE001 - tomllib raises its own type
            raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    # Allow both a flat file and one with sections such as [scan], [similarity].
    flat: Dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict) and key != "category_dirs":
            flat.update(value)
        else:
            flat[key] = value
    return flat


def apply_overrides(cfg: Config, values: Dict[str, Any]) -> Config:
    known = {f.name for f in fields(cfg)}
    for key, value in values.items():
        key = key.replace("-", "_")
        if key not in known:
            raise ConfigError(f"unknown configuration key: {key}")
        if value is None:
            continue
        if key in _PATH_FIELDS:
            value = Path(os.path.expanduser(str(value)))
        elif key in _PATH_LIST_FIELDS:
            value = [Path(os.path.expanduser(str(v))) for v in value]
        setattr(cfg, key, value)
    return cfg
