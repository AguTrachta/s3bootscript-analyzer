"""Ports required by analysis orchestration and evaluation."""

from __future__ import annotations

from typing import Protocol

from s3bootscript_analyzer.analysis.models import (
    AnalysisReport,
    BindingSet,
    ProfileSelection,
)
from s3bootscript_analyzer.analysis.profile import AnalysisProfile, JsonObject


class RuleExecutionError(RuntimeError):
    """Operational plugin or condition failure contained at rule scope."""


class ConditionEvaluator(Protocol):
    """Compile and evaluate a trusted embedded expression language."""

    def compile(self, expression: str) -> object:
        """Compile a validated expression once for one rule."""
        raise NotImplementedError

    def evaluate(
        self,
        condition: object,
        bindings: BindingSet,
        profile: JsonObject,
    ) -> bool:
        """Evaluate captures and JSON facts without domain-specific interpretation."""
        raise NotImplementedError


class AnalysisProfileLoader(Protocol):
    """Load one immutable engine-facing profile selection."""

    def load(self, selection: ProfileSelection) -> AnalysisProfile:
        """Load the explicit profile or the configured default."""
        raise NotImplementedError


class ReportRenderer(Protocol):
    """Render a complete analysis report without writing it."""

    def render(self, report: AnalysisReport) -> str:
        """Return the formatted report text."""
        raise NotImplementedError
