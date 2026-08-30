"""Profile generation contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from s3bootscript_analyzer.profile_data.models import PlatformProfile


class ProfileLoader(ABC):
    """Load a platform profile from a concrete source."""

    @abstractmethod
    def load(self) -> PlatformProfile:
        """Load and parse a platform profile."""
        raise NotImplementedError


class ProfileWriter(ABC):
    """Write a generated platform profile."""

    @abstractmethod
    def write(self, profile: PlatformProfile, output_path: Path) -> None:
        """Write a generated platform profile."""
        raise NotImplementedError
