"""Text IR rendering and output."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from s3bootscript_analyzer.engine.decoders import (
    UNKNOWN_MNEMONIC,
    get_opcode_fields,
    get_opcode_mnemonic,
)
from s3bootscript_analyzer.engine.formatting import (
    MISSING_FIELD_TEXT,
    format_bytes,
    format_integer,
    format_semantic_value,
)
from s3bootscript_analyzer.errors import OutputWriteError
from s3bootscript_analyzer.parsers.raw import (
    RawBootScript,
    RawOpcodeRecord,
    RawTableHeader,
)

LINE_SEPARATOR = "\n"
TRAILING_LINE_SEPARATOR = "\n"
JSON_INDENT = 2
FIELD_RAW = "raw"
SEMANTIC_COLUMN = 120
SEMANTIC_COLUMN_VERBOSE = 160
SEMANTIC_SEPARATOR = " | "
SEMANTIC_ANNOTATIONS: dict[str, str] = {
    "IO_READ_WRITE": "io[address] <- (io[address] & data_mask) | data",
    "MEM_READ_WRITE": "mem[address] <- (mem[address] & data_mask) | data",
    "PCI_CONFIG_READ_WRITE": "pci[address] <- (pci[address] & data_mask) | data",
    "PCI_CONFIG2_READ_WRITE": ("pci[segment:address] <- (pci[segment:address] & data_mask) | data"),
    "IO_WRITE": "io[address] <- buffer",
    "MEM_WRITE": "mem[address] <- buffer",
    "PCI_CONFIG_WRITE": "pci[address] <- buffer",
    "PCI_CONFIG2_WRITE": "pci[segment:address] <- buffer",
    "IO_POLL": "poll until (io[address] & data_mask) == data",
    "MEM_POLL": "poll until (mem[address] & data_mask) == data",
    "PCI_CONFIG_POLL": "poll until (pci[address] & data_mask) == data",
    "PCI_CONFIG2_POLL": "poll until (pci[segment:address] & data_mask) == data",
    "DISPATCH": "call entry_point",
    "DISPATCH_2": "call entry_point(context)",
    "STALL": "stall(duration)",
    "INFORMATION": "info(information)",
    "SMBUS_EXECUTE": "smbus_execute(...)",
}


class BootScriptRenderer(Protocol):
    """Render a parsed boot script into an output format."""

    def render(
        self,
        raw_script: RawBootScript,
        header_text: str,
        opcode_lines: Sequence[str],
    ) -> str:
        """Render output from a raw boot script and decoded text lines."""
        raise NotImplementedError


class TextIrRenderer:
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
        return self.render_lines(header_text, rendered_lines)

    def render_lines(self, header_text: str, opcode_lines: Sequence[str]) -> str:
        return LINE_SEPARATOR.join((header_text, *opcode_lines)) + TRAILING_LINE_SEPARATOR


class JsonIrRenderer:
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


class SemanticIrRenderer:
    """Render resolved semantic expressions only."""

    def render(
        self,
        raw_script: RawBootScript,
        _header_text: str,
        _opcode_lines: Sequence[str],
    ) -> str:
        lines = _render_semantic_lines(raw_script.records)
        return LINE_SEPARATOR.join(lines) + TRAILING_LINE_SEPARATOR


def _render_header(header: RawTableHeader) -> dict[str, int | str]:
    return {
        "magic": format_integer(header.magic),
        "length": header.length,
        "version": format_integer(header.version),
        "table_length": header.table_length,
    }


def _render_record(record: RawOpcodeRecord) -> dict[str, object]:
    return {
        "offset": format_integer(record.offset),
        "mnemonic": get_opcode_mnemonic(record.opcode_id),
        "opcode": format_integer(record.opcode_id),
        "length": record.length,
        "payload": record.payload_size(),
        "fields": _render_fields(record),
    }


def _render_fields(record: RawOpcodeRecord) -> dict[str, str]:
    if get_opcode_mnemonic(record.opcode_id) == UNKNOWN_MNEMONIC:
        return {FIELD_RAW: format_bytes(record.raw_bytes)}
    return {
        field.name: field.format_value(record.body)
        for field in get_opcode_fields(record.opcode_id)
    }


def _render_semantic_lines(records: Sequence[RawOpcodeRecord]) -> list[str]:
    return [
        rendered_line for record in records
        if (rendered_line := _render_semantic_record(record)) is not None
    ]


def _render_semantic_record(record: RawOpcodeRecord) -> str | None:
    template = _semantic_annotation(record)
    if template is None:
        return None
    rendered = template
    semantic_fields = {
        field.name: format_semantic_value(getattr(record.body, field.name, MISSING_FIELD_TEXT))
        for field in get_opcode_fields(record.opcode_id)
    }
    for field_name in sorted(semantic_fields, key=len, reverse=True):
        rendered = rendered.replace(field_name, semantic_fields[field_name])
    return rendered


def _annotate_opcode_lines(
    records: Sequence[RawOpcodeRecord], opcode_lines: Sequence[str], verbose: bool
) -> list[str]:
    return [
        _annotate_opcode_line(record, line, verbose)
        for record, line in zip(records, opcode_lines, strict=True)
    ]


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
    return SEMANTIC_ANNOTATIONS.get(get_opcode_mnemonic(record.opcode_id))


def write_text_output(text: str, output_path: Path | None) -> None:
    if output_path is None:
        print(text, end="")
        return
    try:
        output_path.write_text(text, encoding="utf-8")
    except OSError as ex:
        raise OutputWriteError(f"Unable to write output text '{output_path}': {ex}") from ex
