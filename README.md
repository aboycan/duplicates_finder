# duplicate_finder

A cross-platform (Windows 10/11, Linux, macOS) duplicate media finder written in Python.

It finds duplicate **images, videos and audio** (and any other file) **by content**, keeps one
original of every duplicate group exactly where it is, and moves the surplus copies into a
`Duplicates` folder through a journaled, verify-before-remove transaction.

**It never deletes a retained original, never overwrites an existing file, and the default mode
changes nothing at all.**

```
python -m duplicate_finder scan ~/Pictures              # dry run: show what would happen
python -m duplicate_finder scan ~/Pictures --auto       # move verified exact duplicates
python -m duplicate_finder restore                      # put everything back
```

---

## Contents

1. [Installation](#installation) (Windows, Linux, macOS)
2. [Quick start](#quick-start)
3. [Modes](#modes)
4. [CLI reference and examples](#cli-reference-and-examples)
5. [Exact matching vs. similarity matching](#exact-matching-vs-similarity-matching)
6. [What happens to my files](#what-happens-to-my-files)
7. [Recovery and restore](#recovery-and-restore) (details: [docs/RECOVERY.md](docs/RECOVERY.md))
8. [Reports, logs and the manifest](#reports-logs-and-the-manifest)
9. [Configuration](#configuration)
10. [Performance tuning](#performance-tuning) (details: [docs/PERFORMANCE.md](docs/PERFORMANCE.md))
11. [Adding file types](#adding-file-types) (details: [docs/EXTENDING.md](docs/EXTENDING.md))
12. [Testing](#testing)
13. [Known limitations and security](#known-limitations-and-security) (details: [docs/SAFETY.md](docs/SAFETY.md))

Architecture and the project tree: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Installation

Requires **Python 3.9 or newer**. The exact-duplicate engine, dry run, moves, recovery and
restore use only the standard library. Everything else is optional.

| Optional component | Enables | Install |
|---|---|---|
| Pillow | image similarity, `--validate-media` for images | `pip install Pillow` |
| ImageHash | standard pHash/dHash (a built-in implementation is used otherwise) | `pip install ImageHash` |
| pillow-heif | HEIC/HEIF decoding in similarity mode | `pip install pillow-heif` |
| mutagen | audio metadata without FFmpeg | `pip install mutagen` |
| FFmpeg (`ffmpeg`, `ffprobe`) | video similarity, audio similarity, audio/video metadata | see below |
| Chromaprint (`fpcalc`) | strongest audio fingerprint | see below |
| tomli | full TOML config parser on Python 3.9/3.10 (a built-in subset parser is used otherwise) | `pip install tomli` |

Run `python -m duplicate_finder types` at any time to see what is available on your machine.

### Windows 10 / 11

```powershell
# from the project folder, e.g. E:\ai\utility\duplicates_finder
py -3 -m venv .venv
.venv\Scripts\activate
pip install -e .[all]          # or: pip install -e .   (core only)
winget install Gyan.FFmpeg     # optional, for audio/video similarity
# optional: fpcalc.exe from https://acoustid.org/chromaprint, placed on PATH
python -m duplicate_finder scan "D:\Photos"
```

Paths containing spaces must be quoted. If PowerShell blocks `activate`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.venv\Scripts\python.exe` directly.

### Linux

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[all]'
sudo apt install ffmpeg libchromaprint-tools     # Debian/Ubuntu (optional)
sudo dnf install ffmpeg chromaprint-tools        # Fedora (optional, RPM Fusion for ffmpeg)
python -m duplicate_finder scan ~/Pictures
```

### macOS

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[all]'
brew install ffmpeg chromaprint                  # optional
python -m duplicate_finder scan ~/Pictures
```

macOS may ask for permission (Full Disk Access) the first time the terminal reads folders such
as Desktop, Documents or Photos. Scanning the inside of the Photos library package is possible
but strongly discouraged: let Photos manage its own library.

Without installing, you can also run from the project folder: `python -m duplicate_finder ...`.
After `pip install`, a `duplicate-finder` command is also available.

---

## Quick start

```bash
# 1. See what would happen (default: dry run, nothing is changed)
python -m duplicate_finder scan ~/Pictures ~/Downloads

# 2. Review interactively and approve moves one by one
python -m duplicate_finder scan ~/Pictures --interactive

# 3. Or move every verified exact duplicate automatically
python -m duplicate_finder scan ~/Pictures --auto --destination ~/Duplicates

# 4. Changed your mind? Put everything back
python -m duplicate_finder restore
```

By default the destination is a folder named `Duplicates` **next to** the first scan root
(e.g. scanning `D:\Photos` uses `D:\Duplicates`), laid out as `Images/`, `Videos/`, `Audio/`, `Other/`.

---

## Modes

| Mode | Flag | Changes files? | Moves |
|---|---|---|---|
| Dry run (default) | `--dry-run` | no | shows the copy kept, each copy to move and its destination |
| Report only | `--report-only` | no | writes JSON/CSV/text reports |
| Interactive | `--interactive` | after confirmation | only moves you approve; similar media need you to type `yes` per file |
| Automatic | `--auto` | yes | **only verified exact binary duplicates**; never similar media |
| Recovery | `recover` command | reconciles | resumes or rolls back interrupted moves from the journal |
| Restore | `restore` command | yes | moves relocated files back without overwriting |

Detection mode is chosen separately with `--mode exact|similarity|all` (default `exact`).

---

## CLI reference and examples

```
python -m duplicate_finder scan PATH [PATH ...] [options]
python -m duplicate_finder recover [--rollback]
python -m duplicate_finder restore [--scan-id ID] [--tx TX ...] [--restore-to DIR] [--dry-run] [-y]
python -m duplicate_finder manifest [--format csv|json] [--output FILE] [--redact-paths]
python -m duplicate_finder cache stats|clear
python -m duplicate_finder types
```

Common `scan` options:

| Option | Meaning |
|---|---|
| `--mode exact\|similarity\|all` | what to look for (default `exact`) |
| `--dry-run` / `--report-only` / `--interactive` / `--auto` | what to do (default dry run) |
| `--destination DIR` | where duplicates go (must not contain a scan root) |
| `--layout category\|flat\|mirror` | `mirror` keeps the source folder structure under the category folder |
| `--verify bytes` | after SHA-256, compare every duplicate byte-for-byte with the original |
| `--keep oldest,shortest-path` | rules for choosing the copy to keep (see below) |
| `--prefer DIR` | prefer keeping copies that live under DIR (repeatable) |
| `--types image,video` | restrict to categories (`image,video,audio,other`) |
| `--exclude-dir NAME` / `--exclude-file PATTERN` | extra exclusions (glob patterns, repeatable) |
| `--min-size 1K` / `--max-size 4G` | size filters |
| `--follow-symlinks` | follow links whose targets are inside the scan roots (default: skip and report) |
| `--hardlinks-as-duplicates` | treat hard links to the same file as separate copies (default: no) |
| `--workers N` / `--chunk-size 4M` | I/O tuning |
| `--no-cache` | ignore cached hashes |
| `--stability-seconds 60` | skip files modified in the last 60 s (may still be downloading/copying) |
| `--validate-media` | decode images to report corrupt files |
| `--report json` (repeatable) / `--report none` | report formats (default json+csv+text) |
| `--report-dir DIR` / `--redact-paths` | report location; replace your home folder with `~` |
| `--state-dir DIR` | database/journal location |
| `--config FILE` | TOML or JSON configuration |
| `-y` | skip the final "execute now?" question in interactive mode |
| `-q` | no progress output |

More examples:

```bash
# Exact duplicates across two drives, keep copies on the first drive, byte-verify
python -m duplicate_finder scan /mnt/photos /mnt/backup --keep root-order,oldest --verify bytes --auto

# Windows: keep the copies in the "Master" folder, mirror folder structure in Duplicates
python -m duplicate_finder scan "D:\Photos" --prefer "D:\Photos\Master" --layout mirror --interactive

# Similar images, resized or re-encoded copies: report only
python -m duplicate_finder scan ~/Pictures --mode similarity --review-required --report-only

# Everything, JSON report only
python -m duplicate_finder scan ~/Media --mode all --report json

# Only videos larger than 10 MB
python -m duplicate_finder scan ~/Videos --types video --min-size 10M

# Export the manifest of everything that was moved
python -m duplicate_finder manifest --format csv --output moved.csv
```

Exit codes: `0` success, `1` finished with failures, `2` usage/configuration error,
`3` refused for safety (e.g. an unrecovered interrupted operation), `130` cancelled.

### Which copy is kept

Rules are applied in order until one decides; the full path is always the final tie-breaker, so
the result never depends on scan order. Default: `prefer-paths, root-order, oldest, shortest-path, path`.

| Rule | Keeps |
|---|---|
| `prefer-paths` | a copy under a `--prefer` folder |
| `root-order` | a copy under an earlier scan root on the command line |
| `oldest` / `newest` | the earliest / latest modification time |
| `shortest-path` | the copy with the fewest folder levels |
| `shortest-name` / `longest-name` | by filename length |
| `path` | alphabetical full path |

The report states, for every group, which rule decided.

---

## Exact matching vs. similarity matching

**Exact (binary) duplicates** — the authoritative default:

1. files are grouped by size (different sizes can never be identical);
2. large same-size files are pre-filtered by hashing their first and last 64 KiB;
3. survivors are hashed completely with SHA-256 (streamed in chunks, so memory stays bounded);
4. with `--verify bytes`, every member is additionally compared byte-for-byte with the group's first member.

Files are exact duplicates only if their full contents are identical. Names, dates and sizes are
never evidence. Empty files are exact duplicates of each other. Hard links to one file are one
file, not two copies.

**Similar media** — optional (`--mode similarity` or `all`), clearly separated, never automatic:

| Type | Evidence used | Typical cause |
|---|---|---|
| Images | perceptual hashes (pHash + dHash), aspect ratio, dimensions | resized, re-compressed, converted (PNG→JPEG) |
| Audio | Chromaprint fingerprint (`fpcalc`), else FFmpeg loudness envelope; duration gate | transcoded, different bitrate or tags |
| Video | duration gate + perceptual hashes of sampled frames (FFmpeg), resolution/fps as evidence | re-encoded, resized, remuxed |

Results are classified as:

1. **exact_binary_duplicate** — byte-identical; may be moved automatically.
2. **probable_media_duplicate** — strong perceptual/acoustic evidence; needs your approval.
3. **similar_media_requires_review** — weaker evidence (or metadata only); needs your approval.

Metadata alone (duration, tags, resolution) never makes a probable match; it can at most raise a
review hint. Edited photos, crops, overlays and bursts can look alike while being different
pictures, which is why similarity results are never moved without explicit per-file approval
(in interactive mode you have to type `yes` for each one).

---

## What happens to my files

* Dry run and report-only never modify, move, create or delete anything in your folders
  (the tool writes only its own database, journal and reports in the state directory).
* In interactive/auto mode each move is one journaled transaction:
  re-check the file is unchanged → re-hash the duplicate **and** the kept original from disk →
  journal the intent → claim a new name in `Duplicates` without overwriting
  (hard link on the same drive, exclusive-create copy across drives) → fsync and re-read the copy
  to verify it → re-check source, original and destination once more → only then remove the
  duplicate's old name.
* If anything fails the duplicate stays where it was and the reason is reported. A file is never
  shown as "moved" before the destination has been verified.
* A name collision in `Duplicates` produces `photo__duplicate_001.jpg`, `..._002` and so on.
* Ctrl+C stops after the current file; press it twice to abort immediately (recoverable).

The full safety model is in [docs/SAFETY.md](docs/SAFETY.md).

> **Moving vs. copying.** Moving a duplicate necessarily removes that *copy's* old path after
> the verified relocation; the kept original is never touched. If you need every original path to
> stay populated, use dry run / report-only and act on the report yourself.

---

## Recovery and restore

* `recover` reads the journal and finishes (or, with `--rollback`, abandons) any move that was
  interrupted by a crash, power loss or forced abort. It never deletes anything.
  New organising runs refuse to start while interrupted operations exist.
* `restore` moves relocated files back to their original paths, verifying content first and
  never overwriting. If an original path is occupied, both files are kept and the item is reported
  as a conflict; re-run with `--restore-to DIR` to put such files in another folder (or answer
  the prompt in a terminal). Use `--scan-id` or `--tx` to restore selectively and `--dry-run` to preview.

See [docs/RECOVERY.md](docs/RECOVERY.md).

---

## Reports, logs and the manifest

Every scan writes `report-<scan id>.json`, `.csv` and `.txt` into the state directory's `reports`
folder (or `--report-dir`). For each group: group id, retained original, duplicate paths, size,
SHA-256, classification and confidence, media type, proposed/actual destination, status, reason
and timestamp. Unreadable files, permission problems, extension mismatches, links and other
issues are listed, never silently skipped.

State directory (override with `--state-dir` or `DUPFINDER_STATE_DIR`):

| OS | Default |
|---|---|
| Windows | `%LOCALAPPDATA%\duplicate_finder` |
| macOS | `~/Library/Application Support/duplicate_finder` |
| Linux | `$XDG_STATE_HOME/duplicate_finder` or `~/.local/state/duplicate_finder` |

It contains `state.sqlite3` (hash cache, scan history, operations), `journal.jsonl` (append-only
transaction journal, the source of truth for recovery/restore) and `reports/`.
`manifest` exports every relocated file with its original path. File contents are never logged.

---

## Configuration

Copy [`config.sample.toml`](config.sample.toml), edit it, and pass `--config my.toml`.
Command-line options override the file. JSON configuration files (`.json`) are also accepted.

---

## Performance tuning

* `--workers`: 1–2 for spinning disks and network shares, 4–8 for SSD/NVMe.
* `--chunk-size`: 1 MiB default; 4–8 MiB can help on fast local disks.
* Re-scans reuse cached hashes for files whose device, inode, size, mtime and ctime are all
  unchanged (Linux/macOS). Anything that is moved is always re-hashed from disk first.
* Exclude folders you know are irrelevant (`--exclude-dir`), restrict types (`--types`) or sizes.

Measured on a cloud VM: 20,000 files (13,000 same-size candidates) in about 6.5 s cold and
4.7 s with a warm cache. See [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

---

## Adding file types

Implement a `FileTypeHandler` (formats, signature check, optional metadata/validation) and register
it in code, through `plugins = ["module"]` in the config, `--plugin module`, or the
`duplicate_finder.handlers` entry point. Similarity detectors subclass `SimilarityDetector`.
The exact engine never depends on handlers. See [docs/EXTENDING.md](docs/EXTENDING.md).

---

## Testing

```bash
python -m pytest            # if pytest is installed
python -m unittest discover -s tests -t .   # standard library only
```

The suite (104 tests) builds temporary trees and covers all 24 required scenarios, including
dry-run immutability, never removing or overwriting the retained original, collisions, files
changing between scan and move, cross-filesystem fallbacks, simulated crashes and recovery,
restore conflicts, links, permissions, Unicode, malicious names, cancellation and database
corruption. A static test asserts that the package contains exactly one file-removal call
(the guarded last step of a verified move). Tests needing FFmpeg, Pillow, symlink privileges or
non-root permissions skip themselves when unavailable.

---

## Known limitations and security

* Cross-filesystem moves are copy + verify + remove; they are **not atomic**. The journal makes
  them recoverable.
* Hash caching is trusted only where `ctime` is a real change time (Linux/macOS). On Windows
  full hashes are always recomputed.
* Copies made across filesystems keep content, timestamps and permission bits, but not extended
  attributes, ACLs, macOS resource forks or NTFS alternate data streams. Same-drive moves (hard
  link) keep everything.
* Network shares (SMB/NFS) may not support hard links, may report inode 0 or coarse timestamps,
  and may not honour fsync; the tool falls back to verified copies and is slower there.
* Another program changing files while the tool runs is detected (stat + hash re-checks), but a
  change in the instant between the final check and the removal cannot be fully excluded on any OS.
* Windows paths longer than 260 characters need the "LongPathsEnabled" setting.
* Similarity detection is heuristic. It cannot guarantee finding every re-encoded or edited copy,
  and it can flag different-but-similar pictures (bursts). That is why it never moves anything by itself.
* Files you cannot read are reported, not processed. No administrator/root rights are needed.

More detail, including the threat model: [docs/SAFETY.md](docs/SAFETY.md).
