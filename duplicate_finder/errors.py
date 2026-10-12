"""Exception hierarchy.

Every error raised deliberately by the application derives from
:class:`DuplicateFinderError` so callers can distinguish expected operational
failures from programming errors.
"""

from __future__ import annotations


class DuplicateFinderError(Exception):
    """Base class for all application errors."""


class ConfigError(DuplicateFinderError):
    """Invalid or inconsistent configuration."""


class SafetyViolation(DuplicateFinderError):
    """An operation was refused because it would break a safety invariant.

    These are never caught-and-ignored: they abort the single operation that
    triggered them and are reported to the user.
    """


class PathOutsideAllowedRoot(SafetyViolation):
    """A path resolved outside the directory it was required to stay within."""


class SourceChanged(SafetyViolation):
    """A file changed between verification and the moment it was to be moved."""


class VerificationFailed(SafetyViolation):
    """Copied/linked data did not match the expected content."""


class CancelledError(DuplicateFinderError):
    """The user requested cancellation (Ctrl+C or programmatic)."""


class DatabaseError(DuplicateFinderError):
    """The state database is unusable (corrupt, wrong schema, locked)."""


class JournalError(DuplicateFinderError):
    """The transaction journal could not be written or parsed."""
