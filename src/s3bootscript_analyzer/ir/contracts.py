"""Matcher-facing contracts for semantic text and binary evidence."""

from abc import ABC, abstractmethod


class SemanticSource(ABC):
    """Binary source reference returned by a semantic document."""

    @property
    @abstractmethod
    def record_index(self) -> int:
        """Binary record position."""

    @property
    @abstractmethod
    def opcode_offset(self) -> int:
        """Binary opcode byte offset."""


class SemanticDocument(ABC):
    """Minimal semantic IR behavior required by the output adapter."""

    @property
    @abstractmethod
    def text(self) -> str:
        """Read-only semantic source text."""

    @abstractmethod
    def source_for_line(self, line: int) -> SemanticSource:
        """Resolve a one-based semantic line to binary evidence."""
