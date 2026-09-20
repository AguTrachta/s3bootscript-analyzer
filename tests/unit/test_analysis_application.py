"""Behavior contract for reduced artifact-analysis orchestration."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from s3bootscript_analyzer.analysis import (
    AnalysisEngine,
    AnalysisProfile,
    AnalysisProfileLoader,
    AnalysisRequest,
    AnalysisSetupError,
    AnalyzeArtifact,
    ConditionEvaluator,
    Diagnostic,
    JsonObject,
    MatchEvidence,
    ProfileSelection,
    RuleDefinition,
    Severity,
)
from s3bootscript_analyzer.extensions import AnalysisDocument, AnalysisPlugin, PluginCatalog
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.profile_data import JsonProfileLoader
from s3bootscript_analyzer.rules import RuleLoader, RuleLoadResult, RuleSource, YamlRuleLoader


class StaticDocument(AnalysisDocument):
    plugin_id = "s3bootscript"
    diagnostics = (Diagnostic("unsupported_opcode", "Skipped opcode", "artifact.bin"),)


class StaticPlugin(AnalysisPlugin):
    plugin_id = "s3bootscript"

    def decode(self, _source: BinarySource) -> AnalysisDocument:
        return StaticDocument()

    def match(
        self,
        _document: AnalysisDocument,
        _rule: RuleDefinition,
    ) -> Iterable[MatchEvidence]:
        return (_evidence(),)


class StaticRuleLoader(RuleLoader):
    def __init__(self, result: RuleLoadResult) -> None:
        self._result = result

    def load(
        self,
        _sources: Sequence[RuleSource],
        _plugin: AnalysisPlugin,
    ) -> RuleLoadResult:
        return self._result


class StaticProfileLoader(AnalysisProfileLoader):
    def load(self, _selection: ProfileSelection) -> AnalysisProfile:
        return AnalysisProfile(name="test-profile", data={})


class AcceptingConditions(ConditionEvaluator):
    def __init__(self) -> None:
        self.profiles: list[JsonObject] = []

    def compile(self, expression: str) -> object:
        return expression

    def evaluate(
        self,
        _condition: object,
        _bindings: Mapping[str, bool | float | int | str],
        profile: JsonObject,
    ) -> bool:
        self.profiles.append(profile)
        return True


def test_analyze_artifact_returns_report_context_evaluations_and_diagnostics() -> None:
    rule_diagnostic = Diagnostic("invalid_rule", "Ignored invalid rule", "broken.yaml")
    rule_load = RuleLoadResult(rules=(_rule(),), diagnostics=(rule_diagnostic,))
    use_case = AnalyzeArtifact(
        plugins=PluginCatalog([StaticPlugin()]),
        rules=StaticRuleLoader(rule_load),
        profiles=StaticProfileLoader(),
        engine=AnalysisEngine(AcceptingConditions()),
    )

    report = use_case.execute(_request())

    assert report.artifact_name == "artifact.bin"
    assert report.plugin_id == "s3bootscript"
    assert report.profile_name == "test-profile"
    assert report.evaluations[0].rule.rule_id == "S3-001"
    assert report.evaluations[0].evidence == (_evidence(),)
    assert report.diagnostics == (rule_diagnostic, *StaticDocument.diagnostics)


def test_analyze_artifact_rejects_a_run_without_valid_compatible_rules() -> None:
    use_case = AnalyzeArtifact(
        plugins=PluginCatalog([StaticPlugin()]),
        rules=StaticRuleLoader(RuleLoadResult(rules=(), diagnostics=())),
        profiles=StaticProfileLoader(),
        engine=AnalysisEngine(AcceptingConditions()),
    )

    with pytest.raises(AnalysisSetupError):
        use_case.execute(_request())


def test_original_json_reaches_condition_adapter_through_real_loaders() -> None:
    root = Path(__file__).resolve().parents[2]
    profile_path = root / "profiles/examples/kernel.profile.json"
    rule_path = root / "rules/base/kernel-write.rule.yaml"
    conditions = AcceptingConditions()
    use_case = AnalyzeArtifact(
        plugins=PluginCatalog([StaticPlugin()]),
        rules=YamlRuleLoader(),
        profiles=JsonProfileLoader(),
        engine=AnalysisEngine(conditions),
    )
    report = use_case.execute(
        replace(
            _request(),
            rule_sources=(RuleSource(rule_path.name, rule_path.read_text(encoding="utf-8")),),
            profile_selection=ProfileSelection(profile_path),
        )
    )

    assert report.profile_name == profile_path.name
    assert report.evaluations[0].rule.rule_id == "S3-KERNEL-WRITE-001"
    assert conditions.profiles[0]["ranges"] == (
        {"name": "KERNEL_CODE_RANGE", "start": 4096, "end": 8191, "source_label": "Kernel code"},
    )


def _request() -> AnalysisRequest:
    return AnalysisRequest(
        artifact=BinarySource(path=Path("artifact.bin"), data=b"data"),
        plugin_id="s3bootscript",
        rule_sources=(RuleSource("rule.yaml", "rule"),),
        profile_selection=ProfileSelection(),
    )


def _rule() -> RuleDefinition:
    return RuleDefinition(
        rule_id="S3-001",
        plugin_id="s3bootscript",
        title="Test",
        description="",
        severity=Severity.WARNING,
        enabled=True,
        required_fields=(),
        matcher_type="ast_grep",
        matcher_config={},
    )


def _evidence() -> MatchEvidence:
    return MatchEvidence(
        bindings={"ADDR": 0x1000},
        semantic_text="mem[0x1000] <- 0x1",
        semantic_line=1,
        record_index=0,
        opcode_offset=0x0D,
    )
