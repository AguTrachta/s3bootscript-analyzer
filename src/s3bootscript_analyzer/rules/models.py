"""Rule-ingestion values and its application-facing port."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from s3bootscript_analyzer.analysis.models import Diagnostic, RuleDefinition

if TYPE_CHECKING:
    from s3bootscript_analyzer.extensions import AnalysisPlugin


@dataclass(frozen=True)
class RuleSource:
    """Named untrusted YAML input supplied at runtime."""

    name: str
    text: str


@dataclass(frozen=True)
class RuleLoadResult:
    """Valid rules and recoverable diagnostics in source order."""

    rules: tuple[RuleDefinition, ...]
    diagnostics: tuple[Diagnostic, ...]


class RuleLoader(Protocol):
    """Load analyzer rules compatible with the selected plugin."""

    def load(
        self,
        sources: Sequence[RuleSource],
        plugin: AnalysisPlugin,
    ) -> RuleLoadResult:
        """Load valid rules while preserving recoverable diagnostics."""
        raise NotImplementedError
