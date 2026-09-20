"""Executable contract for normalizing ast-grep JSON into typed candidates."""

import json
from types import SimpleNamespace
from typing import Any

import pytest

ast_grep = pytest.importorskip(
    "s3bootscript_analyzer.matchers.ast_grep",
    reason="The ast-grep adapter is a future core-engine increment",
)
AstGrepJsonDecoder: Any = ast_grep.AstGrepJsonDecoder
AstGrepOutputError: Any = ast_grep.AstGrepOutputError


class StaticSemanticDocument:
    text = "call 0x8000\n"

    def source_for_line(self, line: int) -> SimpleNamespace:
        assert line == 1
        return SimpleNamespace(record_index=4, opcode_offset=0x52)


def test_decoder_normalizes_captures_and_restores_binary_evidence() -> None:
    payload = _payload(
        text="call 0x8000",
        single={
            "ENTRY": {"text": "0x8000"},
            "COUNT": {"text": "12"},
            "NAME": {"text": "dispatch"},
        },
    )

    evidence = AstGrepJsonDecoder().decode_stream([json.dumps(payload)], StaticSemanticDocument())

    assert len(evidence) == 1
    match = evidence[0]
    assert match.bindings == {"ENTRY": 0x8000, "COUNT": 12, "NAME": "dispatch"}
    assert match.semantic_text == "call 0x8000"
    assert match.semantic_line == 1
    assert match.record_index == 4
    assert match.opcode_offset == 0x52


def test_decoder_preserves_match_order_and_ignores_blank_stream_lines() -> None:
    first = _payload(text="call 0x8000", single={"ENTRY": {"text": "0x8000"}})
    second = _payload(text="call 0x9000", single={"ENTRY": {"text": "0x9000"}})

    evidence = AstGrepJsonDecoder().decode_stream(
        [json.dumps(first), "", json.dumps(second)], StaticSemanticDocument()
    )

    assert [match.bindings["ENTRY"] for match in evidence] == [0x8000, 0x9000]


@pytest.mark.parametrize(
    "line",
    [
        "not-json",
        json.dumps({"text": "call 0x8000", "metaVariables": {}}),
        json.dumps(
            {
                "text": "call 0x8000",
                "range": {"start": {"line": "zero"}},
                "metaVariables": {},
            }
        ),
    ],
)
def test_decoder_reports_malformed_backend_output(line: str) -> None:
    with pytest.raises(AstGrepOutputError):
        AstGrepJsonDecoder().decode_stream([line], StaticSemanticDocument())


def _payload(text: str, single: dict[str, dict[str, str]]) -> dict[str, object]:
    return {
        "file": "semantic.txt",
        "text": text,
        "range": {
            "start": {"line": 0, "column": 0},
            "end": {"line": 0, "column": len(text)},
        },
        "metaVariables": {"single": single, "multi": {}},
    }
