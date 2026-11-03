"""Executable behavior contract for the reduced analysis engine."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

import pytest
from hypothesis import example, given
from hypothesis import strategies as st

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
    SimpleEvalConditionEvaluator,
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


class RuleEvidencePlugin(StaticPlugin):
    def __init__(self, matches: Mapping[str, tuple[MatchEvidence, ...]]) -> None:
        super().__init__()
        self._matches = matches

    def match(
        self,
        _document: AnalysisDocument,
        rule: RuleDefinition,
    ) -> tuple[MatchEvidence, ...]:
        return self._matches[rule.rule_id]


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


def test_engine_preserves_only_accepted_candidates_in_source_order() -> None:
    # Arrange
    candidates = _candidates(0x1000, 0x2000, 0x3000, 0x4000)

    # Act
    evaluation = AnalysisEngine(SimpleEvalConditionEvaluator()).evaluate(
        StaticDocument(),
        [_rule(condition="ENTRY in [0x2000, 0x4000]")],
        _profile(),
        StaticPlugin(candidates),
    )[0]

    # Assert
    assert evaluation.outcome is EvaluationOutcome.MATCHED
    assert evaluation.evidence == (candidates[1], candidates[3])
    assert evaluation.diagnostics == ()


def test_late_candidate_failure_discards_partial_evidence_and_later_rule_matches() -> None:
    # Arrange
    candidates = _candidates(0x1000, 0x2000, 0x3000)
    rules = [
        _rule(rule_id="first", condition='ENTRY < 0x3000 or record["missing"]'),
        _rule(rule_id="later"),
    ]

    # Act
    evaluations = AnalysisEngine(SimpleEvalConditionEvaluator()).evaluate(
        StaticDocument(),
        rules,
        _profile(),
        RuleEvidencePlugin({"first": candidates, "later": (candidates[0],)}),
    )

    # Assert
    assert [evaluation.rule.rule_id for evaluation in evaluations] == ["first", "later"]
    assert evaluations[0].outcome is EvaluationOutcome.ERROR
    assert evaluations[0].evidence == ()
    assert len(evaluations[0].diagnostics) == 1
    assert evaluations[0].diagnostics[0].code == "rule_execution_error"
    assert evaluations[0].diagnostics[0].source == "first"
    assert "missing" in evaluations[0].diagnostics[0].message
    assert evaluations[1].outcome is EvaluationOutcome.MATCHED
    assert evaluations[1].evidence == (candidates[0],)
    assert evaluations[1].diagnostics == ()


def test_engine_reports_unknown_when_required_profile_facts_are_missing() -> None:
    plugin = StaticPlugin([_evidence()])
    rule = _rule(required_fields=("trusted_execution",))

    evaluations = _engine().evaluate(StaticDocument(), [rule], _profile(), plugin)

    assert evaluations[0].outcome is EvaluationOutcome.UNKNOWN
    assert evaluations[0].rule == rule
    assert evaluations[0].diagnostics[0].source == rule.rule_id
    assert evaluations[0].diagnostics[0].message.endswith("trusted_execution")
    assert plugin.calls == 0


def _json_values(depth: int) -> st.SearchStrategy[object]:
    scalars = st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-(2**64), max_value=2**64 - 1),
        st.floats(allow_nan=False, allow_infinity=False),
        st.text(max_size=12),
    )
    if depth == 0:
        return scalars
    children = _json_values(depth - 1)
    return st.one_of(
        scalars,
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=12), children, max_size=4),
    )


@dataclass(frozen=True)
class RequiredProfileCase:
    required: tuple[str, ...]
    facts: dict[str, object]
    removed: str


@st.composite
def _required_profile_case(
    draw: st.DrawFn,
) -> RequiredProfileCase:
    required = tuple(
        draw(st.lists(st.sampled_from(["fact", "flag", "count", "a.b"]), min_size=1, unique=True))
    )
    values = draw(st.lists(_json_values(3), min_size=len(required), max_size=len(required)))
    facts = dict(zip(required, values, strict=True))
    facts["a"] = {"b": "nested lookalike is not a literal key"}
    facts["unrelated"] = draw(_json_values(3))
    return RequiredProfileCase(required, facts, draw(st.sampled_from(required)))


@pytest.mark.property
@given(case=_required_profile_case())
@example(case=RequiredProfileCase(("a.b",), {"a.b": False, "a": {"b": True}}, "a.b"))
@example(case=RequiredProfileCase(("count",), {"count": 0}, "count"))
@example(case=RequiredProfileCase(("fact",), {"fact": ""}, "fact"))
@example(case=RequiredProfileCase(("fact",), {"fact": []}, "fact"))
@example(case=RequiredProfileCase(("fact",), {"fact": {}}, "fact"))
@example(case=RequiredProfileCase(("fact",), {"fact": None}, "fact"))
def test_required_fact_presence_controls_public_analysis_outcome(
    case: RequiredProfileCase,
) -> None:
    # Arrange
    complete = AnalysisProfile(name="complete", data=case.facts)
    incomplete = AnalysisProfile(
        name="incomplete",
        data={key: value for key, value in case.facts.items() if key != case.removed},
    )
    rule = _rule(required_fields=case.required)

    # Act
    present = _engine().evaluate(StaticDocument(), [rule], complete, StaticPlugin([_evidence()]))[0]
    missing = _engine().evaluate(StaticDocument(), [rule], incomplete, StaticPlugin([_evidence()]))[
        0
    ]

    # Assert
    assert present.outcome is EvaluationOutcome.MATCHED
    assert present.evidence == (_evidence(),)
    assert present.diagnostics == ()
    assert missing.outcome is EvaluationOutcome.UNKNOWN
    assert missing.evidence == ()
    assert len(missing.diagnostics) == 1
    assert missing.diagnostics[0].code == "missing_profile_data"
    assert missing.diagnostics[0].message.endswith(case.removed)


def test_engine_skips_disabled_rules_without_calling_plugin() -> None:
    plugin = StaticPlugin([_evidence()])
    rule = _rule(rule_id="disabled", enabled=False, required_fields=("unavailable",))

    evaluations = _engine().evaluate(
        StaticDocument(),
        [rule],
        _profile(),
        plugin,
    )

    assert evaluations[0].outcome is EvaluationOutcome.SKIPPED
    assert evaluations[0].rule == rule
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
@pytest.mark.parametrize("condition", [None, "True"], ids=["no-condition", "condition"])
def test_reserved_capture_is_an_error_with_or_without_a_condition(
    reserved_name: str, condition: str | None
) -> None:
    # Arrange
    conflicting = replace(_evidence(), bindings={reserved_name: "capture"})

    # Act
    evaluations = AnalysisEngine(SimpleEvalConditionEvaluator()).evaluate(
        StaticDocument(),
        [_rule(rule_id="conflict", condition=condition), _rule(rule_id="later")],
        _profile(),
        RuleEvidencePlugin({"conflict": (conflicting,), "later": (_evidence(),)}),
    )

    # Assert
    assert evaluations[0].outcome is EvaluationOutcome.ERROR
    assert evaluations[0].evidence == ()
    assert len(evaluations[0].diagnostics) == 1
    assert evaluations[0].diagnostics[0].code == "rule_execution_error"
    assert reserved_name in evaluations[0].diagnostics[0].message
    assert evaluations[1].rule.rule_id == "later"
    assert evaluations[1].outcome is EvaluationOutcome.MATCHED
    assert evaluations[1].evidence == (_evidence(),)
    assert evaluations[1].diagnostics == ()


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


def _candidates(*addresses: int) -> tuple[MatchEvidence, ...]:
    return tuple(
        MatchEvidence(
            bindings={"ENTRY": address},
            semantic_text=f"call {address:#x}",
            semantic_line=index + 1,
            record_index=index,
            opcode_offset=index,
            record={"address": address},
        )
        for index, address in enumerate(addresses)
    )


def _profile() -> AnalysisProfile:
    return AnalysisProfile(name="test", data={})
