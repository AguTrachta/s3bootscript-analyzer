"""Binary ingestion components."""

from __future__ import annotations

from s3bootscript_analyzer.ingest.file_loader import FileLoader
from s3bootscript_analyzer.ingest.source import BinarySource

__all__ = ["BinarySource", "FileLoader"]
