"""Project-specific exceptions."""

from __future__ import annotations


class BootScriptAnalyzerError(Exception):
    """Base error for expected analyzer failures."""


class BinaryLoadError(BootScriptAnalyzerError):
    """Raised when an input binary cannot be loaded."""


class OutputWriteError(BootScriptAnalyzerError):
    """Raised when text output cannot be written."""


class RawParseError(BootScriptAnalyzerError):
    """Raised when raw boot script parsing cannot produce a valid model."""
