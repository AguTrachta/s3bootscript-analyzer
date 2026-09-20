"""Declarative rule loading API."""

from s3bootscript_analyzer.analysis.models import Diagnostic, RuleDefinition, Severity
from s3bootscript_analyzer.rules.loader import YamlRuleLoader
from s3bootscript_analyzer.rules.models import RuleLoader, RuleLoadResult, RuleSource

__all__ = [
    "Diagnostic",
    "RuleDefinition",
    "RuleLoader",
    "RuleLoadResult",
    "RuleSource",
    "Severity",
    "YamlRuleLoader",
]
