"""Allow ``python -m duplicate_finder``."""

import sys

from .cli import main

if __name__ == "__main__":  # pragma: no cover - thin wrapper
    sys.exit(main())
