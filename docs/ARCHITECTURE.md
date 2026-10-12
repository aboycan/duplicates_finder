# Architecture

## Project tree

```
duplicates_finder/
├── pyproject.toml              packaging, optional extras, console script
├── requirements.txt            optional dependencies with compatible versions
├── config.sample.toml          documented sample configuration
├── README.md
├── docs/
│   ├── ARCHITECTURE.md         this file
│   ├── SAFETY.md               invariants, threat model, security, limitations
│   ├── RECOVERY.md             journal, recover, restore, manifest
│   ├── PERFORMANCE.md          tuning guidance
│   └── EXTENDING.md            adding file types and detectors
├── duplicate_finder/
│   ├── __main__.py             python -m duplicate_finder
│   ├── cli.py                  argparse CLI, interactive approval, exit codes
│   ├── config.py               Config dataclass, defaults, TOML/JSON loading, validation
│   ├── models.py               FileRecord, DuplicateGroup, PlannedMove, enums
│   ├── errors.py               exception hierarchy (SafetyViolation, ...)
│   ├── safety.py               containment, sanitising, same-file checks
│   ├── runtime.py              CancelToken, Progress
│   ├── scanner.py              traversal, exclusions, symlink/hard-link policy
│   ├── file_types.py           signature detection, FileTypeHandler, registry
│   ├── media_probe.py          optional ffprobe/ffmpeg/fpcalc wrappers (no shell, timeouts)
│   ├── hashing.py              chunked SHA-256, partial hash, byte comparison
│   ├── database.py             SQLite: hash cache, scans, operations; migrations
│   ├── grouping.py             exact matcher, bounded concurrency, original selection
│   ├── detectors/
│   │   ├── base.py             SimilarityDetector, SimilarityMatch, union-find grouping
│   │   ├── image.py            pHash + dHash (+ BK-tree search)
│   │   ├── audio.py            Chromaprint / PCM envelope / metadata-only review
│   │   └── video.py            duration gate + sampled-frame hashes
│   ├── organizer.py            planning, safe move transaction, the single removal point
│   ├── transaction_log.py      append-only fsync'd journal, process lock
│   ├── recovery.py             recover, restore, manifest
│   ├── reporting.py            JSON / CSV / text reports
│   └── pipeline.py             Engine: orchestrates the stages
└── tests/                      104 unittest/pytest tests
```

## Data flow

```
roots ──► Scanner ──► FileRecord[] ──► classify (HandlerRegistry) ──► category filter
                                                                        │
                ┌───────────────────────────────────────────────────────┤
                ▼                                                       ▼
        ExactMatcher                                         Similarity detectors
  size → partial hash → SHA-256 → (bytes)                 (image / audio / video, optional)
        │   ▲ hash cache (SQLite)                                       │
        ▼                                                               ▼
  DuplicateGroup[EXACT]                                  DuplicateGroup[PROBABLE|REVIEW]
                └──────────────────────┬────────────────────────────────┘
                                       ▼
                              Organizer.plan  (destinations, collision-free names; read-only)
                                       │
         dry-run / report ◄────────────┤
                                       ▼
                 auto: approve EXACT only │ interactive: user approves per file
                                       ▼
                              Organizer.execute ──► Journal (fsync) ──► filesystem
                                       │
                                       ▼
                         reports (JSON/CSV/text) + DB scan summary
```

## Design choices

* **Core independent of media libraries.** `grouping`, `hashing`, `organizer`, `recovery` import
  nothing outside the standard library. Pillow/FFmpeg are touched only by handlers and detectors,
  and only when available.
* **Journal over database for durability.** SQLite is a cache and an index; the append-only
  journal is what recovery and restore trust, because an fsync'd append is simpler to reason
  about after a crash than a database page.
* **Exclusive creation instead of check-then-write.** Every new name is claimed with
  `os.link` or `O_EXCL`, which closes the race between "does it exist?" and "write it".
* **Hard link as the same-filesystem move.** Linking the source to the destination is atomic,
  cannot overwrite, keeps all metadata, and lets the destination be verified (same inode) before
  the source name is removed. Copy is the fallback for cross-device or link-less filesystems.
* **One removal function.** All removals go through `_remove_source_after_verified_move`, which
  re-validates everything immediately before acting; a static test keeps it that way.
* **Bounded concurrency.** `bounded_map` keeps at most `2 × workers` reads in flight, so memory
  stays flat for millions of files and disks are not flooded.
* **Determinism.** Directory entries are processed in name order; the original is chosen by an
  explicit rule list ending in the full path; group ids derive from content hash + member paths.

## Extension points

* `FileTypeHandler` + `HandlerRegistry.register` / plugin modules / entry points (see EXTENDING.md)
* `SimilarityDetector` + `register_detector`
* Keep rules (`config.KEEP_CRITERIA`, `grouping._sort_key`)
* Destination layouts (`Organizer.destination_dir`)
