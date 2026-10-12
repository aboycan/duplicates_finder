"""Duplicate File Finder and Organizer.

A cross-platform tool that finds duplicate media files by *content*, and safely
relocates surplus copies into a ``Duplicates`` folder.  The tool never deletes
the retained original of any duplicate group, never overwrites an existing
file, and journals every relocation so it can be recovered or restored.

See ``docs/SAFETY.md`` for the safety invariants the code is built around.
"""

__version__ = "1.0.0"

__all__ = ["__version__"]
