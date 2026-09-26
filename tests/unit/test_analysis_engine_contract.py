"""Executable behavior contract for the reduced analysis engine."""

from collections.abc import Iterable, Mapping
from dataclasses import replace

import pytest

from s3bootscript_analyzer.analysis import (
    AnalysisEngine,
    AnalysisProfile,
    ConditionEvaluator,
    Diagnostic,
    EvaluationOutcome,
    JsonObject,
    MatchEvidence,
    RuleDefinition,
    RuleExecutionError,
    Severity,
)
from s3bootscript_analyzer.extensions import AnalysisDocument, AnalysisPlugin
from s3bootscript_analyzer.ingest import BinarySource


class StaticDocument(AnalysisDocument):
    plugin_id = "s3bootscript"
    diagnostics: tuple[Diagnostic, ...] = ()


class StaticPlugin(AnalysisPlugin):
    plugin_id = "s3bootscript"

    def __init__(
        self,
        evidence: Iterable[MatchEvidence] = (),
        failure: str | None = None,
    ) -> None:
        self._evidence = tuple(evidence)
        self._failure = failure
        self.calls = 0

    def decode(self, _source: BinarySource) -> StaticDocument:
        return StaticDocument()

    def match(
        self,
        _document: AnalysisDocument,
        _rule: RuleDefinition,
    ) -> tuple[MatchEvidence, ...]:
        self.calls += 1
        if self._failure is not None:
            raise RuleExecutionError(self._failure)
        return self._evidence


class StaticConditionEvaluator(ConditionEvaluator):
    def __init__(self, result: bool = True) -> None:
        self._result = result
        self.compiled: list[str] = []
        self.activations: list[
            tuple[Mapping[str, bool | float | int | str], JsonObject, JsonObject]
        ] = []

    def compile(self, expression: str) -> object:
        self.compiled.append(expression)
        return expression

    def evaluate(
        self,
        _condition: object,
        bindings: Mapping[str, bool | float | int | str],
        profile: JsonObject,
        record: JsonObject,
    ) -> bool:
        self.activations.append((bindings, profile, record))
        return self._result


def test_engine_matches_evidence_without_an_optional_condition() -> None:
    plugin = StaticPlugin([_evidence()])

    evaluations = _engine().evaluate(StaticDocument(), [_rule()], _profile(), plugin)

    assert evaluations[0].outcome is EvaluationOutcome.MATCHED
    assert evaluations[0].evidence == (_evidence(),)
    assert plugin.calls == 1


def test_engine_reports_not_matched_when_plugin_finds_no_evidence() -> None:
    evaluations = _engine().evaluate(StaticDocument(), [_rule()], _profile(), StaticPlugin())

    assert evaluations[0].outcome is EvaluationOutcome.NOT_MATCHED
    assert evaluations[0].evidence == ()


def test_engine_filters_evidence_with_the_existing_expression_backend() -> None:
    evaluator = StaticConditionEvaluator(result=False)
    rule = _rule(condition="ENTRY == 0x8000")

    evaluations = _engine(evaluator).evaluate(
        StaticDocument(),
        [rule],
        _profile(),
        StaticPlugin([_evidence()]),
    )

    assert evaluations[0].outcome is EvaluationOutcome.NOT_MATCHED
    assert evaluator.compiled == [rule.condition]
    assert len(evaluator.activations) == 1


def test_engine_reports_unknown_when_required_profile_facts_are_missing() -> None:
    plugin = StaticPlugin([_evidence()])
    rule = _rule(required_fields=("trusted_execution",))

    evaluations = _engine().evaluate(StaticDocument(), [rule], _profile(), plugin)

    assert evaluations[0].outcome is EvaluationOutcome.UNKNOWN
    assert evaluations[0].diagnostics[0].message.endswith("trusted_execution")
    assert plugin.calls == 0


def test_engine_skips_disabled_rules_without_calling_plugin() -> None:
    plugin = StaticPlugin([_evidence()])

    evaluations = _engine().evaluate(
        StaticDocument(),
        [_rule(enabled=False, required_fields=("unavailable",))],
        _profile(),
        plugin,
    )

    assert evaluations[0].outcome is EvaluationOutcome.SKIPPED
    assert plugin.calls == 0


@pytest.mark.parametrize("facts", [{"ranges": []}, {"limits": {"maximum": 128}}, {"ids": ["a"]}])
def test_engine_passes_arbitrary_profile_facts_to_evaluator(facts: dict[str, object]) -> None:
    evaluator = StaticConditionEvaluator()
    profile = AnalysisProfile(name="producer", data=facts)
    rule = _rule(required_fields=tuple(facts), condition="True")

    evaluation = _engine(evaluator).evaluate(
        StaticDocument(), [rule], profile, StaticPlugin([_evidence()])
    )[0]

    assert evaluation.outcome is EvaluationOutcome.MATCHED
    assert evaluator.activations == [(_evidence().bindings, profile.data, _evidence().record)]


@pytest.mark.parametrize("reserved_name", ["profile", "record"])
def test_reserved_capture_is_an_error_even_without_a_condition(reserved_name: str) -> None:
    conflicting = replace(_evidence(), bindings={reserved_name: "capture"})

    evaluations = _engine().evaluate(
        StaticDocument(), [_rule()], _profile(), StaticPlugin([conflicting])
    )

    assert evaluations[0].outcome is EvaluationOutcome.ERROR
    assert reserved_name in evaluations[0].diagnostics[0].message


class FailingConditions(StaticConditionEvaluator):
    def compile(self, _expression: str) -> object:
        raise RuleExecutionError("Invalid condition syntax")


def test_bad_condition_is_contained_before_matching_and_later_rules_continue() -> None:
    plugin = StaticPlugin([_evidence()])
    rules = [_rule(condition="broken"), _rule(rule_id="later")]

    evaluations = AnalysisEngine(FailingConditions()).evaluate(
        StaticDocument(), rules, _profile(), plugin
    )

    assert [result.outcome for result in evaluations] == [
        EvaluationOutcome.ERROR,
        EvaluationOutcome.MATCHED,
    ]
    assert plugin.calls == 1


def test_missing_profile_fact_does_not_prevent_a_later_rule_from_matching() -> None:
    first = _rule(required_fields=("limits",))
    second = replace(first, rule_id="later", required_fields=())

    evaluations = _engine().evaluate(
        StaticDocument(), [first, second], _profile(), StaticPlugin([_evidence()])
    )

    assert [result.outcome for result in evaluations] == [
        EvaluationOutcome.UNKNOWN,
        EvaluationOutcome.MATCHED,
    ]


def test_engine_contains_plugin_failure_and_continues_in_rule_order() -> None:
    rules = [_rule(rule_id="S3-001"), _rule(rule_id="S3-002")]

    evaluations = _engine().evaluate(
        StaticDocument(),
        rules,
        _profile(),
        StaticPlugin(failure="ast-grep failed"),
    )

    assert [evaluation.rule.rule_id for evaluation in evaluations] == ["S3-001", "S3-002"]
    assert [evaluation.outcome for evaluation in evaluations] == [
        EvaluationOutcome.ERROR,
        EvaluationOutcome.ERROR,
    ]
    assert all(evaluation.diagnostics for evaluation in evaluations)


def test_evaluation_outcome_is_independent_from_rule_severity() -> None:
    evaluations = _engine().evaluate(
        StaticDocument(),
        [_rule(severity=Severity.CRITICAL)],
        _profile(),
        StaticPlugin(),
    )

    evaluation = evaluations[0]
    assert evaluation.rule.severity is Severity.CRITICAL
    assert evaluation.outcome is EvaluationOutcome.NOT_MATCHED


def _engine(evaluator: StaticConditionEvaluator | None = None) -> AnalysisEngine:
    return AnalysisEngine(condition_evaluator=evaluator or StaticConditionEvaluator())


def _rule(
    rule_id: str = "S3-001",
    enabled: bool = True,
    severity: Severity = Severity.WARNING,
    required_fields: tuple[str, ...] = (),
    condition: str | None = None,
) -> RuleDefinition:
    return RuleDefinition(
        rule_id=rule_id,
        plugin_id="s3bootscript",
        title="Test rule",
        description="",
        severity=severity,
        enabled=enabled,
        required_fields=required_fields,
        matcher_type="ast_grep",
        matcher_config={"language": "s3boot"},
        condition=condition,
    )


def _evidence() -> MatchEvidence:
    return MatchEvidence(
        bindings={"ENTRY": 0x8000},
        semantic_text="call 0x8000",
        semantic_line=1,
        record_index=0,
        opcode_offset=0x0D,
    )


def _profile() -> AnalysisProfile:
    return AnalysisProfile(name="test", data={})
