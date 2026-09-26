"""Evaluate declarative conditions over captures and generic JSON facts."""

import ast

from simpleeval import EvalWithCompoundTypes, InvalidExpression

from s3bootscript_analyzer.analysis.contracts import ConditionEvaluator, RuleExecutionError
from s3bootscript_analyzer.analysis.models import BindingSet
from s3bootscript_analyzer.analysis.profile import JsonObject


class SimpleEvalConditionEvaluator(ConditionEvaluator):
    """Compile expressions once and isolate each candidate's evaluation."""

    def compile(self, expression: str) -> ast.expr:
        try:
            return ast.parse(expression.strip(), mode="eval").body
        except SyntaxError as error:
            raise RuleExecutionError(str(error)) from error

    def evaluate(
        self,
        condition: object,
        bindings: BindingSet,
        profile: JsonObject,
        record: JsonObject,
    ) -> bool:
        if "profile" in bindings:
            raise RuleExecutionError("Capture cannot replace reserved name 'profile'")
        if "record" in bindings:
            raise RuleExecutionError("Capture cannot replace reserved name 'record'")
        result = _evaluate_expression(condition, {**bindings, "profile": profile, "record": record})
        if not isinstance(result, bool):
            raise RuleExecutionError("Condition must return a boolean")
        return result


def _evaluate_expression(condition: object, names: dict[str, object]) -> object:
    """Translate expression failures into rule-scoped errors."""
    try:
        return EvalWithCompoundTypes(names=names, functions={"any": any}, allowed_attrs={}).eval(
            "", previously_parsed=condition
        )
    except (InvalidExpression, LookupError, TypeError, ValueError, ArithmeticError) as error:
        raise RuleExecutionError(str(error)) from error
