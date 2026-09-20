"""Generic rule evaluation through one trusted plugin facade."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from s3bootscript_analyzer.analysis.contracts import (
    ConditionEvaluator,
    RuleExecutionError,
)
from s3bootscript_analyzer.analysis.models import (
    Diagnostic,
    EvaluationOutcome,
    MatchEvidence,
    RuleDefinition,
    RuleEvaluation,
)
from s3bootscript_analyzer.analysis.profile import (
    AnalysisProfile,
    JsonObject,
    MissingProfileDataError,
)
from s3bootscript_analyzer.extensions import AnalysisDocument, AnalysisPlugin


class AnalysisEngine:
    """Evaluate independent typed rules while containing adapter failures."""

    def __init__(self, condition_evaluator: ConditionEvaluator) -> None:
        self._condition_evaluator = condition_evaluator

    def evaluate(
        self,
        document: AnalysisDocument,
        rules: Sequence[RuleDefinition],
        profile: AnalysisProfile,
        plugin: AnalysisPlugin,
    ) -> tuple[RuleEvaluation, ...]:
        """Evaluate rules in stable input order."""
        return tuple(self._evaluate_rule(document, rule, profile, plugin) for rule in rules)

    def _evaluate_rule(
        self,
        document: AnalysisDocument,
        rule: RuleDefinition,
        profile: AnalysisProfile,
        plugin: AnalysisPlugin,
    ) -> RuleEvaluation:
        if not rule.enabled:
            return _evaluation(rule, EvaluationOutcome.SKIPPED)
        try:
            profile.require_fields(rule.required_fields)
            return self._execute_rule(document, rule, profile, plugin)
        except MissingProfileDataError as ex:
            return _unknown_evaluation(rule, ex)
        except RuleExecutionError as ex:
            return _error_evaluation(rule, ex)

    def _execute_rule(
        self,
        document: AnalysisDocument,
        rule: RuleDefinition,
        profile: AnalysisProfile,
        plugin: AnalysisPlugin,
    ) -> RuleEvaluation:
        compiled_condition = self._compile_condition(rule)
        return _evidence_evaluation(
            rule,
            self._accepted_evidence(plugin.match(document, rule), compiled_condition, profile.data),
        )

    def _compile_condition(self, rule: RuleDefinition) -> object | None:
        if rule.condition is None:
            return None
        return self._condition_evaluator.compile(rule.condition)

    def _accepted_evidence(
        self,
        matches: Iterable[MatchEvidence],
        compiled_condition: object | None,
        profile: JsonObject,
    ) -> tuple[MatchEvidence, ...]:
        return tuple(
            evidence for evidence in matches if self._accept(evidence, compiled_condition, profile)
        )

    def _accept(
        self,
        evidence: MatchEvidence,
        compiled_condition: object | None,
        profile: JsonObject,
    ) -> bool:
        if compiled_condition is None:
            return True
        return self._condition_evaluator.evaluate(
            compiled_condition,
            evidence.bindings,
            profile,
        )


def _evidence_evaluation(
    rule: RuleDefinition, evidence: tuple[MatchEvidence, ...]
) -> RuleEvaluation:
    outcome = EvaluationOutcome.MATCHED if evidence else EvaluationOutcome.NOT_MATCHED
    return _evaluation(rule, outcome, evidence)


def _evaluation(
    rule: RuleDefinition,
    outcome: EvaluationOutcome,
    evidence: tuple[MatchEvidence, ...] = (),
    diagnostics: tuple[Diagnostic, ...] = (),
) -> RuleEvaluation:
    return RuleEvaluation(
        rule=rule,
        outcome=outcome,
        evidence=evidence,
        diagnostics=diagnostics,
    )


def _unknown_evaluation(
    rule: RuleDefinition,
    error: MissingProfileDataError,
) -> RuleEvaluation:
    diagnostic = Diagnostic(
        code="missing_profile_data",
        message=str(error),
        source=rule.rule_id,
    )
    return _evaluation(rule, EvaluationOutcome.UNKNOWN, diagnostics=(diagnostic,))


def _error_evaluation(rule: RuleDefinition, error: RuleExecutionError) -> RuleEvaluation:
    diagnostic = Diagnostic(
        code="rule_execution_error",
        message=str(error),
        source=rule.rule_id,
    )
    return _evaluation(rule, EvaluationOutcome.ERROR, diagnostics=(diagnostic,))
