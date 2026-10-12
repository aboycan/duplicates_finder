# Performance tuning

## How work is reduced

1. **Size grouping** — free; files with a unique size are never opened for hashing.
2. **Partial hash** — for same-size files over 256 KiB, SHA-256 of size + first 64 KiB + last
   64 KiB rules out most non-duplicates (typical for media of identical length but different content).
3. **Full SHA-256** — only for survivors, streamed in `chunk_size` pieces.
4. **Byte comparison** (`--verify bytes`) — only within groups that already share a hash.
5. **Hash cache** — SQLite; reused only when device, inode, size, mtime and ctime all match
   (Linux/macOS). Re-scans of unchanged trees hash almost nothing.

Type identification reads the first 4 KiB of each file.

## Settings

| Setting | Default | Guidance |
|---|---|---|
| `workers` | 4 | HDD / USB 2 / network share: 1–2 (parallel reads cause seeking). SATA SSD: 4. NVMe: 6–8. |
| `chunk_size` | 1 MiB | 4–8 MiB on fast local disks; 256 KiB–1 MiB on network shares. |
| `use_cache` | on | Disable (`--no-cache`) only for forensics-style runs. |
| `verify` | sha256 | `bytes` reads every duplicate twice more; use for the highest assurance. |
| `min_size` | 0 | Raising it (e.g. `--min-size 1K`) skips tiny sidecar files quickly. |
| `exclude_dirs` | VCS, caches, trash, system folders | Add build/output folders you know are irrelevant. |
| `video_samples` | 5 | Fewer samples = faster video similarity, less evidence. |

Similarity analysis is far more expensive than exact matching (image decoding, FFmpeg decoding).
Run `--mode similarity` on narrowed folders or types (`--types image`).

## Memory

Memory is proportional to the number of files (one small record each, ~300–500 bytes) plus
`workers × 2 × chunk_size` for in-flight reads. Millions of files need a few GB of RAM; split very
large collections into several runs by root if memory is tight.

## Measured

Cloud VM, local SSD, 20,000 files of 1–20 KB, 13,052 same-size candidates, 50 groups / 1,950 copies:

| Run | Time |
|---|---|
| cold (no cache) | 6.5 s |
| warm cache | 4.7 s (time dominated by directory walk + type detection) |

## Progress and cancellation

Progress is shown on stderr (every 0.5 s on a terminal, every 5 s when redirected). `-q` disables it.
Ctrl+C stops after the current file and still writes a (partial) report; a second Ctrl+C aborts
immediately — run `recover` afterwards if a move was in flight.
