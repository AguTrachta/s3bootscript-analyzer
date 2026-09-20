"""Application orchestration for one artifact analysis."""

from __future__ import annotations

from dataclasses import dataclass

from s3bootscript_analyzer.analysis.contracts import AnalysisProfileLoader
from s3bootscript_analyzer.analysis.engine import AnalysisEngine
from s3bootscript_analyzer.analysis.models import AnalysisReport, ProfileSelection
from s3bootscript_analyzer.extensions import PluginCatalog
from s3bootscript_analyzer.ingest.source import BinarySource
from s3bootscript_analyzer.rules.models import RuleLoader, RuleSource


class AnalysisSetupError(RuntimeError):
    """Raised when an analysis cannot start with the supplied inputs."""


@dataclass(frozen=True)
class AnalysisRequest:
    """Immutable inputs selected for one artifact analysis."""

    artifact: BinarySource
    plugin_id: str
    rule_sources: tuple[RuleSource, ...]
    profile_selection: ProfileSelection


@dataclass(frozen=True)
class AnalyzeArtifact:
    """Coordinate trusted extensions and core services without adapter logic."""

    plugins: PluginCatalog
    rules: RuleLoader
    profiles: AnalysisProfileLoader
    engine: AnalysisEngine

    def execute(self, request: AnalysisRequest) -> AnalysisReport:
        """Run one analysis and return a report-ready application value."""
        plugin = self.plugins.resolve(request.plugin_id)
        rule_load = self.rules.load(request.rule_sources, plugin)
        if not rule_load.rules:
            raise AnalysisSetupError("Analysis requires at least one valid compatible rule")
        document = plugin.decode(request.artifact)
        profile = self.profiles.load(request.profile_selection)
        return AnalysisReport(
            artifact_name=request.artifact.path.name,
            plugin_id=plugin.plugin_id,
            profile_name=profile.name,
            evaluations=self.engine.evaluate(document, rule_load.rules, profile, plugin),
            diagnostics=(*rule_load.diagnostics, *document.diagnostics),
        )
