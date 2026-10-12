# Recovery and restore

## The journal

`journal.jsonl` in the state directory is an append-only log. Each relocation is a transaction:

```
intent         -> source, retained original, both SHA-256 hashes and stat fingerprints, destination folder
dest_reserved  -> exact destination path and method (link | copy); written right after the name is claimed
dest_verified  -> destination content verified
source_removed -> the duplicate's old name was removed
committed      -> done
failed         -> stopped; state = source_retained | both_present
```

Every event is fsync'd before the filesystem action it announces. The journal is never rewritten;
recovery and restore only append. An exclusive lock prevents two processes from organising at once.

## `recover`

```
python -m duplicate_finder recover            # resume interrupted moves (default)
python -m duplicate_finder recover --rollback # leave sources where they are
```

For every transaction without a terminal event:

| Found on disk | Default (resume) | `--rollback` |
|---|---|---|
| journal says source removed, destination verifies | mark committed | same |
| no destination recorded, source present | mark aborted (nothing happened); any unjournaled hard link of the source is reported | same |
| destination incomplete or missing, source present | mark rolled back; incomplete copy reported (not deleted) | same |
| destination verifies, source present and unchanged, original present and unchanged | **complete the move** via the guarded removal | keep source; report the extra verified copy |
| destination verifies, source or original changed | keep everything, mark rolled back | same |
| source missing, destination verifies | mark committed | same |
| source missing, destination does not verify | **needs attention** (printed with `!!`, exit code 1) | same |

Recovery never deletes a file other than through the same guarded removal used by normal
moves, and only in the "complete the move" row. New `--interactive`/`--auto` runs and `restore`
refuse to start while unreconciled transactions exist.

## `restore`

```
python -m duplicate_finder restore --dry-run              # preview
python -m duplicate_finder restore                        # everything not yet restored (asks to confirm)
python -m duplicate_finder restore --scan-id 20261012-081500-ab12cd
python -m duplicate_finder restore --tx 3f2a... --tx 9b1c...
python -m duplicate_finder restore --restore-to ~/Restored   # destination for conflicts
```

For each committed move (from the manifest) that has not been restored:

1. The file in `Duplicates` must still exist and match the recorded SHA-256 (a file you edited
   in `Duplicates` is skipped and reported).
2. If the original path is free, the file is placed there (parent folders re-created inside the
   original scan root), verified, and only then removed from `Duplicates`.
3. If the original path is occupied, **both files are kept**. Without `--restore-to` the item is
   reported as `conflict` (in a terminal you are asked for a folder). With `--restore-to DIR`
   the file goes to `DIR/<original relative folder>/<name>` and, if that is taken too,
   `<name>__duplicate_001.<ext>` and so on.

Restores are journaled transactions themselves (`kind = restore`), so they are recoverable and
appear in the manifest as `restored = true`.

## Manifest

```
python -m duplicate_finder manifest --format csv --output relocated.csv
```

Columns: transaction id, scan id, group id, match class, original path, retained original,
destination, SHA-256, size, timestamp, restored, restored_to. It is derived from the journal, so
it is complete even if the database was lost.

## If the state directory is lost

Files in `Duplicates` are ordinary files; nothing is hidden or encoded. Without the journal the
automatic restore is unavailable, but the JSON/CSV reports (if kept elsewhere) still map every
destination to its original path.
