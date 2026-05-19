"""Profile generation orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from s3bootscript_analyzer.profile_data.contracts import (
    ProfileParser,
    ProfileSourceReader,
    ProfileWriter,
)


@dataclass(frozen=True)
class GenerateProfile:
    """Coordinate reading, parsing, and writing a generated profile."""

    output_path: Path
    reader: ProfileSourceReader
    parser: ProfileParser
    writer: ProfileWriter

    def run(self) -> None:
        raw_text = self.reader.read()
        profile = self.parser.parse(raw_text)
        self.writer.write(profile, self.output_path)
