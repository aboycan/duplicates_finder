# Safety invariants, threat model and security notes

This document is the contract the code is built around. Each invariant names where it is enforced
and which tests prove it.

## Safety invariants

| # | Invariant | Enforced in | Tests |
|---|---|---|---|
| S1 | The retained original of a group is never moved, modified, or removed. | `organizer._execute_one` (original re-hashed; must be a different file); `_remove_source_after_verified_move` re-checks the original immediately before removal | `test_moves_duplicates_and_keeps_original`, `test_original_modified_before_move`, `test_original_deleted_before_move`, `test_resume_refused_if_original_changed` |
| S2 | No existing file is ever overwritten. | names claimed only via `os.link` or `O_CREAT\|O_EXCL`; reports/manifests opened with mode `"x"` | `test_existing_destination_files_never_overwritten`, `test_collision_appearing_after_planning`, `test_restore_conflict_keeps_both` |
| S3 | Scanned files' contents are never modified. | files are opened read-only; copies are written only to new names | content multiset assertions in the organizer tests |
| S4 | Exactly one code path removes a file: the last step of a verified move/restore. | `organizer._remove_source_after_verified_move` | `NoDeletionStaticTests.test_single_removal_point` (static scan of the package) |
| S5 | A source is removed only after the destination was verified (same inode for a link; SHA-256 re-read from disk for a copy) and the source, destination and original were re-checked. | `reserve_and_transfer`, `_remove_source_after_verified_move` | `test_corrupted_copy_detected`, `test_copy_failure_retains_source`, `test_source_removal_failure_keeps_both` |
| S6 | Nothing is deleted because a move failed. Failed or partial copies are reported, not cleaned up. | organizer and recovery error paths | `test_copy_failure_retains_source`, `test_crash_during_copy_incomplete_destination` |
| S7 | Only exact binary duplicates move without approval. Similarity results can never be "exact". | `pipeline` (auto approves only `EXACT`), `Organizer.execute(allow_similar=False)`, `SimilarityMatch.__post_init__` | `test_auto_never_moves_similar_media`, `test_similarity_match_cannot_be_exact`, `test_edited_image_never_exact_and_never_auto_moved` |
| S8 | Dry run and report-only change nothing in user folders. | `pipeline._run_stages` returns before `execute`; planning uses only `lexists` | `test_dry_run_changes_nothing`, `test_report_only_changes_nothing`, `test_dry_run_default` |
| S9 | Only files inside explicitly given roots are moved, and only into the destination. | `scanner` (roots, symlink policy), `_execute_one` (resolved containment), `assert_within` for every destination | `test_symlinks_skipped_by_default`, `test_follow_symlinks_within_roots_only`, `test_planted_symlink_in_destination_refused`, `test_root_inside_destination_refused` |
| S10 | Files in `Duplicates` and the state directory are never rediscovered. | `Scanner` excludes them by path *and* device/inode identity | `test_destination_inside_root_is_not_rescanned` |
| S11 | A file changed after the scan is not moved. | stat fingerprint check + fresh re-hash before moving; stat checks around every read | `test_source_modified_between_scan_and_move`, `test_change_during_hashing_detected` |
| S12 | Cached hashes never decide a move. | organizer always re-hashes source and original; cache trusted for grouping only where ctime is a change time | `test_cache_hit_and_invalidation`, `test_cache_not_trusted_without_change_time`, `test_stale_entry_rejected_by_fingerprint` |
| S13 | Every intended change is journaled (fsync) before it happens; interrupted transactions are recoverable and block new runs. | `transaction_log.Journal`, `pipeline` pending check, `recovery.recover` | `RecoveryTests`, `test_pending_journal_blocks_new_moves`, `test_append_only_and_torn_line_tolerated` |
| S14 | Hard links and symlinks to one file are one file, not duplicates. | `Scanner._add_file` identity de-duplication | `test_hardlinks_collapsed`, `test_hardlinks_not_moved_as_duplicates` |
| S15 | A file is reported as moved only after verification. | `MoveStatus.MOVED` set after commit; `INCOMPLETE` when the source could not be removed | `test_source_removal_failure_keeps_both` |

### Conservative decisions taken where the requirements were ambiguous

* **Default action is dry run.** Moving requires `--interactive` or `--auto`.
* **Default destination is outside the scanned folder** (next to the first root). A destination
  that *contains* a scan root is refused.
* **Symlinks are skipped by default**, and only followed inside the roots when asked.
* **Hard links are not duplicates** by default.
* **Interrupted transactions block new organising runs** until `recover` has run.
* **Cancellation never interrupts a transaction**; it stops between files.
* **A journal write failure stops all further moves** in that run.
* **Similar groups formed transitively** (A~B, B~C without A~C) are downgraded to "review".
* **Recovery never removes the incomplete copy it finds**; it reports it so you can decide.
* **Corrupt state database** is renamed aside (never deleted) and rebuilt; the journal, not the
  database, is the source of truth.

## Threat model

Assets: the content of every file under the scan roots, especially the last copy of any content.

| Threat | Mitigation |
|---|---|
| Bug or crash removes the only copy | single removal point (S4) with pre-removal checks of original + destination; journal + recovery |
| Wrong match (different files treated as identical) | full-content SHA-256, optional byte comparison; size/name/metadata never decide |
| Stale cache entry | full stat fingerprint match required; never used for moves (S12) |
| File changes between check and use (TOCTOU) | fingerprint checks before/after reads, re-hash before move, final re-check immediately before removal; exclusive name creation |
| Concurrent runs of the tool | exclusive OS lock on the journal (`flock` / `msvcrt.locking`), released automatically if the process dies |
| Overwriting a file in `Duplicates` or at a restore target | `os.link` / `O_EXCL` fail instead of overwriting |
| Path traversal via file names (`../`, absolute paths, drive letters, UNC prefixes, reserved Windows names, control characters) | `sanitize_component` / `safe_relative`; resolved-path containment checks |
| Symlink/junction planted inside `Duplicates` to redirect writes | containment checked on resolved paths after directory creation |
| Symlink or junction inside a root pointing elsewhere | skipped by default; followed only within the roots; Windows junctions treated as links |
| Malicious file names reaching external tools | FFmpeg/ffprobe/fpcalc called with argument arrays, no shell, `file:` prefixed absolute paths, timeouts |
| Torn journal line after power loss | ignored on read; next append starts on a fresh line |
| Sensitive paths in shared reports | `--redact-paths`; contents are never logged |

## Security notes

* No administrator/root privileges are needed or recommended.
* External programs are optional; when used they run with a timeout (`external_timeout`) and
  never through a shell.
* The state directory contains full paths (needed for recovery). Protect it like any other
  personal data; the journal is created with mode `0600` on POSIX.

## Limitations

* **Cross-filesystem moves are not atomic.** They are copy → fsync → verify → remove, and
  journaled so an interruption is recoverable.
* **fsync is best-effort** on network filesystems and some USB devices; a hardware or power
  failure there can still lose recently written data in the *destination* (the source is only
  removed after a verified read-back, so the content survives at least at the source until then).
* **Metadata preserved by copies**: content, modification/access time, permission bits.
  Not preserved: extended attributes, ACLs, ownership (without privileges), macOS resource
  forks/Finder info, NTFS alternate data streams. Same-filesystem moves (hard links) preserve
  everything.
* **Windows**: `st_ctime` is the creation time, so full-hash caching is disabled; open/locked
  files cannot be removed (reported as *incomplete*: both copies kept); paths over 260 characters
  require the OS long-path setting; FAT/exFAT drives do not support hard links (copy fallback).
* **macOS**: case-insensitive, normalisation-insensitive volumes are handled by exclusive
  creation at the OS level; the planner also assumes case-insensitivity when proposing names.
* **Network shares**: inode numbers may be 0 or unstable (identity checks degrade to path and
  size/mtime checks), hard links may be unsupported, timestamps may be coarse.
* **External modification**: a program that rewrites a file in the microseconds between the final
  check and the removal of the duplicate's name cannot be excluded completely on any OS. The
  retained original is checked in the same window and the content exists in the verified copy.
* **Similarity matching is heuristic** and limited by available decoders (HEIC needs
  `pillow-heif`; RAW formats are matched exactly but not perceptually).
