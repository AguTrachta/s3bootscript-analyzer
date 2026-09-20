"""Text IR rendering and output."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Sequence
from itertools import chain
from pathlib import Path

from s3bootscript_analyzer.engine.decoders import (
    UNKNOWN_MNEMONIC,
    get_opcode_fields,
    get_opcode_mnemonic,
)
from s3bootscript_analyzer.engine.formatting import (
    MISSING_FIELD_TEXT,
    format_bytes,
    format_integer,
    format_value,
)
from s3bootscript_analyzer.errors import OutputWriteError
from s3bootscript_analyzer.ir.semantic import SemanticIrBuilder, semantic_annotation
from s3bootscript_analyzer.parsers.raw import (
    RawBootScript,
    RawOpcodeRecord,
    RawTableHeader,
)

LINE_SEPARATOR = "\n"
TRAILING_LINE_SEPARATOR = "\n"
JSON_INDENT = 2
FIELD_RAW = "raw"
SEMANTIC_COLUMN = 115
SEMANTIC_COLUMN_VERBOSE = 160
SEMANTIC_SEPARATOR = " | "
_LOGGER = logging.getLogger(__name__)
RenderedHeader = dict[str, int | str]
RenderedFields = dict[str, str]
RenderedRecord = dict[str, str | int | RenderedFields]


class BootScriptRenderer(ABC):
    """Render a parsed boot script into an output format."""

    @abstractmethod
    def render(
        self,
        raw_script: RawBootScript,
        header_text: str,
        opcode_lines: Sequence[str],
    ) -> str:
        """Render output from a raw boot script and decoded text lines."""


class TextIrRenderer(BootScriptRenderer):
    """Render decoded boot script lines as plain text."""

    def __init__(self, verbose: bool = False) -> None:
        self._verbose = verbose

    def render(
        self,
        raw_script: RawBootScript,
        header_text: str,
        opcode_lines: Sequence[str],
    ) -> str:
        rendered_lines = _annotate_opcode_lines(raw_script.records, opcode_lines, self._verbose)
        return self._render_lines(header_text, rendered_lines)

    def _render_lines(self, header_text: str, opcode_lines: Iterable[str]) -> str:
        return LINE_SEPARATOR.join(chain((header_text,), opcode_lines)) + TRAILING_LINE_SEPARATOR


class JsonIrRenderer(BootScriptRenderer):
    """Render decoded boot script data as structured JSON."""

    def render(
        self,
        raw_script: RawBootScript,
        _header_text: str,
        _opcode_lines: Sequence[str],
    ) -> str:
        data = {
            "header": _render_header(raw_script.table_header),
            "records": [_render_record(record) for record in raw_script.records],
        }
        return json.dumps(data, indent=JSON_INDENT) + TRAILING_LINE_SEPARATOR


class SemanticIrRenderer(BootScriptRenderer):
    """Render resolved semantic expressions only."""

    def render(
        self,
        raw_script: RawBootScript,
        _header_text: str,
        _opcode_lines: Sequence[str],
    ) -> str:
        return SemanticIrBuilder().build(raw_script).text


def _render_header(header: RawTableHeader) -> RenderedHeader:
    return {
        "magic": format_integer(header.magic),
        "length": header.length,
        "version": format_integer(header.version),
        "table_length": header.table_length,
    }


def _render_record(record: RawOpcodeRecord) -> RenderedRecord:
    return {
        "offset": format_integer(record.offset),
        "mnemonic": get_opcode_mnemonic(record.opcode_id),
        "opcode": format_integer(record.opcode_id),
        "length": record.length,
        "payload": record.payload_size(),
        "fields": _render_fields(record),
    }


def _render_fields(record: RawOpcodeRecord) -> RenderedFields:
    if get_opcode_mnemonic(record.opcode_id) == UNKNOWN_MNEMONIC:
        return {FIELD_RAW: format_bytes(record.raw_bytes)}
    return {
        field: format_value(getattr(record.body, field, MISSING_FIELD_TEXT))
        for field in get_opcode_fields(record.opcode_id)
    }


def _annotate_opcode_lines(
    records: Iterable[RawOpcodeRecord], opcode_lines: Iterable[str], verbose: bool
) -> Iterator[str]:
    for record, line in zip(records, opcode_lines, strict=True):
        yield _annotate_opcode_line(record, line, verbose)


def _annotate_opcode_line(record: RawOpcodeRecord, line: str, verbose: bool) -> str:
    semantic_text = _semantic_annotation(record)
    if semantic_text is None:
        return line
    return _annotate_line(line, semantic_text, _semantic_column(verbose))


def _annotate_line(line: str, semantic_text: str, semantic_column: int) -> str:
    if len(line) >= semantic_column:
        return f"{line}{SEMANTIC_SEPARATOR}{semantic_text}"
    padding = " " * (semantic_column - len(line))
    return f"{line}{padding}{SEMANTIC_SEPARATOR}{semantic_text}"


def _semantic_column(verbose: bool) -> int:
    return SEMANTIC_COLUMN_VERBOSE if verbose else SEMANTIC_COLUMN


def _semantic_annotation(record: RawOpcodeRecord) -> str | None:
    return semantic_annotation(record)


def write_text_output(text: str, output_path: Path | None) -> None:
    if output_path is None:
        _LOGGER.debug("writing output target=stdout length=%d", len(text))
        print(text, end="")
        _LOGGER.debug("wrote output target=stdout")
        return
    _LOGGER.debug("writing output path=%s length=%d", output_path, len(text))
    try:
        output_path.write_text(text, encoding="utf-8")
    except OSError as ex:
        raise OutputWriteError(f"Unable to write output text '{output_path}': {ex}") from ex
    _LOGGER.debug("wrote output path=%s", output_path)
