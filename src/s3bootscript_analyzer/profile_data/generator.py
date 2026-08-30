"""Profile generation orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from s3bootscript_analyzer.profile_data.contracts import (
    ProfileLoader,
    ProfileWriter,
)


@dataclass(frozen=True)
class GenerateProfile:
    """Coordinate reading, parsing, and writing a generated profile."""

    output_path: Path
    loader: ProfileLoader
    writer: ProfileWriter

    def run(self) -> None:
        profile = self.loader.load()
        self.writer.write(profile, self.output_path)
