"""Profile generation contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from s3bootscript_analyzer.profile_data.models import PlatformProfile


class ProfileSourceReader(ABC):
    """Read raw profile source text."""

    @abstractmethod
    def read(self) -> str:
        """Read raw profile source text."""
        raise NotImplementedError


class ProfileParser(ABC):
    """Parse raw profile source text into a platform profile."""

    @abstractmethod
    def parse(self, raw_text: str) -> PlatformProfile:
        """Parse raw profile source text into a platform profile."""
        raise NotImplementedError


class ProfileWriter(ABC):
    """Write a generated platform profile."""

    @abstractmethod
    def write(self, profile: PlatformProfile, output_path: Path) -> None:
        """Write a generated platform profile."""
        raise NotImplementedError
