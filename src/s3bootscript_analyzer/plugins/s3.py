"""Trusted S3 Boot Script plugin facade."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import cast

from s3bootscript_analyzer.analysis.contracts import RuleExecutionError
from s3bootscript_analyzer.analysis.models import MatchEvidence, RuleDefinition
from s3bootscript_analyzer.extensions import (
    AnalysisDocument,
    AnalysisPlugin,
    DuplicateExtensionError,
    UnknownExtensionError,
)
from s3bootscript_analyzer.ingest.source import BinarySource
from s3bootscript_analyzer.ir.semantic import (
    S3_BOOT_SCRIPT_PLUGIN_ID,
    SemanticIrBuilder,
    SemanticIrDocument,
)
from s3bootscript_analyzer.parsers.raw import BootScriptRawParser


class _S3Matcher(ABC):
    """Private matcher adapter owned by the S3 plugin."""

    matcher_type: str

    @abstractmethod
    def match(
        self,
        document: SemanticIrDocument,
        config: Mapping[str, object],
    ) -> Iterable[MatchEvidence]:
        """Return evidence in semantic source order."""


class S3BootScriptPlugin(AnalysisPlugin):
    """Facade over existing S3 parsing, semantic IR, and private matchers."""

    plugin_id = S3_BOOT_SCRIPT_PLUGIN_ID

    def __init__(
        self,
        raw_parser: BootScriptRawParser,
        semantic_builder: SemanticIrBuilder,
        matchers: Iterable[_S3Matcher] = (),
    ) -> None:
        self._raw_parser = raw_parser
        self._semantic_builder = semantic_builder
        self._matchers: dict[str, _S3Matcher] = {}
        for matcher in matchers:
            self._register_matcher(matcher)

    def decode(self, source: BinarySource) -> SemanticIrDocument:
        """Reuse the existing raw parser and semantic builder."""
        return self._semantic_builder.build(self._raw_parser.parse(source))

    def match(
        self,
        document: AnalysisDocument,
        rule: RuleDefinition,
    ) -> Iterable[MatchEvidence]:
        """Delegate matching after enforcing plugin compatibility."""
        self._ensure_compatible(document, rule)
        try:
            matcher = self._resolve_matcher(rule.matcher_type)
        except UnknownExtensionError as ex:
            raise RuleExecutionError(str(ex)) from ex
        semantic_document = cast(SemanticIrDocument, document)
        return _attach_records(
            semantic_document, matcher.match(semantic_document, rule.matcher_config)
        )

    def _register_matcher(self, matcher: _S3Matcher) -> None:
        if matcher.matcher_type in self._matchers:
            message = f"Duplicate matcher for plugin={self.plugin_id} type={matcher.matcher_type}"
            raise DuplicateExtensionError(message)
        self._matchers[matcher.matcher_type] = matcher

    def _resolve_matcher(self, matcher_type: str) -> _S3Matcher:
        try:
            return self._matchers[matcher_type]
        except KeyError as ex:
            message = f"Unknown matcher for plugin={self.plugin_id} type={matcher_type}"
            raise UnknownExtensionError(message) from ex

    def _ensure_compatible(
        self,
        document: AnalysisDocument,
        rule: RuleDefinition,
    ) -> None:
        if document.plugin_id != self.plugin_id or rule.plugin_id != self.plugin_id:
            raise RuleExecutionError("S3 plugin received an incompatible document or rule")


def _attach_records(
    document: SemanticIrDocument,
    matches: Iterable[MatchEvidence],
) -> Iterable[MatchEvidence]:
    for evidence in matches:
        try:
            source = document.source_for_line(evidence.semantic_line)
            record = document.records[evidence.record_index]
        except IndexError as ex:
            raise RuleExecutionError(f"Invalid S3 record association: {ex}") from ex
        if (
            evidence.record_index,
            evidence.opcode_offset,
            source.record_index,
            source.opcode_offset,
        ) != (
            record.record_index,
            record.offset,
            record.record_index,
            record.offset,
        ):
            raise RuleExecutionError("S3 evidence does not match its binary record")
        yield replace(evidence, record=record.context)
