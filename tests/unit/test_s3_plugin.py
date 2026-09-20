"""Behavior contract for the trusted S3 plugin facade."""

from collections.abc import Iterable, Mapping
from pathlib import Path

import pytest

from s3bootscript_analyzer.analysis import (
    MatchEvidence,
    RuleDefinition,
    RuleExecutionError,
    Severity,
)
from s3bootscript_analyzer.extensions import DuplicateExtensionError
from s3bootscript_analyzer.ingest import BinarySource
from s3bootscript_analyzer.ir import SemanticIrBuilder, SemanticIrDocument
from s3bootscript_analyzer.parsers.raw import BootScriptRawParser, RawBootScript, RawTableHeader
from s3bootscript_analyzer.plugins import S3BootScriptPlugin
from s3bootscript_analyzer.plugins.s3 import _S3Matcher


class StaticRawParser(BootScriptRawParser):
    def __init__(self) -> None:
        self.sources: list[BinarySource] = []

    def parse(self, source: BinarySource) -> RawBootScript:
        self.sources.append(source)
        return RawBootScript(
            table_header=RawTableHeader(magic=0xAA, length=13, version=1, table_length=13),
            records=[],
        )


class StaticSemanticBuilder(SemanticIrBuilder):
    def __init__(self) -> None:
        self.scripts: list[RawBootScript] = []

    def build(self, raw_script: RawBootScript) -> SemanticIrDocument:
        self.scripts.append(raw_script)
        return SemanticIrDocument(text="", source_map=())


class StaticMatcher(_S3Matcher):
    matcher_type = "ast_grep"

    def match(
        self,
        _document: SemanticIrDocument,
        _config: Mapping[str, object],
    ) -> Iterable[MatchEvidence]:
        return (_evidence(),)


def test_s3_plugin_reuses_existing_parser_and_semantic_builder() -> None:
    parser = StaticRawParser()
    builder = StaticSemanticBuilder()
    plugin = S3BootScriptPlugin(parser, builder)
    source = BinarySource(path=Path("artifact.bin"), data=b"data")

    document = plugin.decode(source)

    assert document.plugin_id == "s3bootscript"
    assert parser.sources == [source]
    assert builder.scripts[0].table_header.magic == 0xAA


def test_s3_plugin_delivers_evidence_from_its_private_adapter() -> None:
    # Arrange
    matcher = StaticMatcher()
    plugin = S3BootScriptPlugin(StaticRawParser(), StaticSemanticBuilder(), [matcher])
    document = SemanticIrDocument(text="call 0x8000\n", source_map=())
    rule = _rule()

    # Act
    evidence = tuple(plugin.match(document, rule))

    # Assert
    assert evidence == (_evidence(),)


def test_s3_plugin_rejects_an_unknown_matcher() -> None:
    # Arrange
    plugin = S3BootScriptPlugin(StaticRawParser(), StaticSemanticBuilder())
    document = SemanticIrDocument(text="call 0x8000\n", source_map=())
    rule = _rule()

    # Act / Assert
    with pytest.raises(RuleExecutionError, match="Unknown matcher.*type=ast_grep"):
        tuple(plugin.match(document, rule))


def test_s3_plugin_rejects_duplicate_matcher_types() -> None:
    with pytest.raises(DuplicateExtensionError):
        S3BootScriptPlugin(
            StaticRawParser(),
            StaticSemanticBuilder(),
            [StaticMatcher(), StaticMatcher()],
        )


def _rule() -> RuleDefinition:
    return RuleDefinition(
        rule_id="S3-001",
        plugin_id="s3bootscript",
        title="Dispatch",
        description="",
        severity=Severity.WARNING,
        enabled=True,
        required_fields=(),
        matcher_type="ast_grep",
        matcher_config={"language": "s3boot"},
    )


def _evidence() -> MatchEvidence:
    return MatchEvidence(
        bindings={"ENTRY": 0x8000},
        semantic_text="call 0x8000",
        semantic_line=1,
        record_index=0,
        opcode_offset=0x0D,
    )
