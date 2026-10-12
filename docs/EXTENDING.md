# Extending duplicate_finder

The exact-duplicate engine works on bytes and does not depend on any handler. Handlers add
**identification** (category, format, extension mismatch reports), optional **metadata**,
optional **validation**, and the category used for the `Duplicates` sub-folder. Similarity
detectors add optional perceptual comparison.

## File-type handlers

```python
from pathlib import Path
from typing import Any, Dict, Optional

from duplicate_finder.file_types import FileTypeHandler, FormatSpec
from duplicate_finder.models import MediaCategory


class PdfHandler(FileTypeHandler):
    name = "pdf"                       # unique
    priority = 50                      # lower = consulted earlier for signatures
    report_fields = ("pages",)
    formats = {
        # format name -> category, MIME type, extensions, optional container family
        "pdf": FormatSpec(MediaCategory.OTHER, "application/pdf", (".pdf",)),
    }

    def identify(self, header: bytes, extension: str) -> Optional[str]:
        return "pdf" if header.startswith(b"%PDF-") else None

    def extract_metadata(self, path: Path, fmt: str) -> Dict[str, Any]:
        return {}                      # must never raise

    def validate(self, path: Path, fmt: str) -> Optional[str]:
        return None                    # return an error message for corrupt files


def register(registry):                # used by --plugin / config "plugins"
    registry.register(PdfHandler())
```

Ways to register:

* code: `duplicate_finder.file_types.default_registry().register(PdfHandler())`
* config: `plugins = ["my_package.pdf_handler"]` (module must define `register(registry)`)
* CLI: `--plugin my_package.pdf_handler`
* packaging entry point:

  ```toml
  [project.entry-points."duplicate_finder.handlers"]
  pdf = "my_package.pdf_handler:register"
  ```

  then call `default_registry().load_entry_points()` in your launcher.

`identify` receives the first 4 KiB of the file. A handler that raises is ignored for that file;
it cannot break a scan. If several formats share a container (like ISO-BMFF for MP4/M4A/MOV),
give them the same `family`; the extension then picks among them without being reported as a
mismatch.

## Similarity detectors

```python
from duplicate_finder.detectors import SimilarityDetector, SimilarityMatch, register_detector
from duplicate_finder.models import MatchClass, MediaCategory


class PdfTextDetector(SimilarityDetector):
    name = "pdf-text"
    categories = {MediaCategory.OTHER}

    def available(self):
        return True, ""

    def find_matches(self, records):
        matches = []
        # ... compare records, append SimilarityMatch(a, b, MatchClass.REVIEW, score, {"method": "..."})
        return matches


register_detector(PdfTextDetector)
```

Rules enforced by the framework:

* a detector may return only `PROBABLE` or `REVIEW` (constructing an `EXACT` match raises);
* similarity groups are never moved automatically; interactive mode asks per file;
* report problems with `self._issue(path, message)` instead of raising;
* honour `self.cancel.check()` in long loops and use `duplicate_finder.grouping.bounded_map` for
  bounded concurrency.
