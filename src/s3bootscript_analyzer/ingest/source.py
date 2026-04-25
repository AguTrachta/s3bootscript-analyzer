"""Binary source domain object."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)  # the instance remains unchanged after it is created
class BinarySource:
    """Loaded binary input and its origin."""

    path: Path
    data: bytes

    def size(self) -> int:
        """Return the binary size in bytes."""

        return len(self.data)
