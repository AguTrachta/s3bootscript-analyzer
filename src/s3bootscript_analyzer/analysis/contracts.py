"""Ports required by analysis orchestration and evaluation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from s3bootscript_analyzer.analysis.models import (
    AnalysisReport,
    BindingSet,
    ProfileSelection,
)
from s3bootscript_analyzer.analysis.profile import AnalysisProfile, JsonObject


class RuleExecutionError(RuntimeError):
    """Operational plugin or condition failure contained at rule scope."""


class ConditionEvaluator(ABC):
    """Compile and evaluate a trusted embedded expression language."""

    @abstractmethod
    def compile(self, expression: str) -> object:
        """Compile a validated expression once for one rule."""

    @abstractmethod
    def evaluate(
        self,
        condition: object,
        bindings: BindingSet,
        profile: JsonObject,
    ) -> bool:
        """Evaluate captures and JSON facts without domain-specific interpretation."""


class AnalysisProfileLoader(ABC):
    """Load one immutable engine-facing profile selection."""

    @abstractmethod
    def load(self, selection: ProfileSelection) -> AnalysisProfile:
        """Load the explicit profile or the configured default."""


class ReportRenderer(ABC):
    """Render a complete analysis report without writing it."""

    @abstractmethod
    def render(self, report: AnalysisReport) -> str:
        """Return the formatted report text."""
