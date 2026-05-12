"""File-based binary loading."""

from __future__ import annotations

import logging
from pathlib import Path

from s3bootscript_analyzer.errors import BinaryLoadError
from s3bootscript_analyzer.ingest.source import BinarySource

_LOGGER = logging.getLogger(__name__)


class FileLoader:
    """Load S3 boot script bytes from a configurable filesystem path."""

    def load(self, path: str | Path) -> BinarySource:
        input_path = Path(path).expanduser()
        _LOGGER.debug("loading input binary path=%s", input_path)
        try:
            data = input_path.read_bytes()
        except OSError as ex:
            raise BinaryLoadError(f"Unable to load input binary '{input_path}': {ex}") from ex
        _LOGGER.debug("loaded input binary path=%s size=%d", input_path, len(data))
        return BinarySource(path=input_path, data=data)
