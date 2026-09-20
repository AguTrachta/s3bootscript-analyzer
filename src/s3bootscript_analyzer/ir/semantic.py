"""Matcher-facing semantic IR for S3 Boot Script records."""

from __future__ import annotations

from dataclasses import dataclass, field

from s3bootscript_analyzer.analysis.models import Diagnostic
from s3bootscript_analyzer.engine.decoders import (
    get_opcode_fields,
    get_opcode_mnemonic,
)
from s3bootscript_analyzer.engine.formatting import MISSING_FIELD_TEXT, format_semantic_value
from s3bootscript_analyzer.extensions import AnalysisDocument
from s3bootscript_analyzer.ir.contracts import SemanticDocument, SemanticSource
from s3bootscript_analyzer.parsers.raw import RawBootScript, RawOpcodeRecord

S3_BOOT_SCRIPT_PLUGIN_ID = "s3bootscript"
LINE_SEPARATOR = "\n"

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


@dataclass(frozen=True, slots=True)
class SemanticSourceReference(SemanticSource):
    """Map one human-readable semantic line to its binary record."""

    semantic_line: int
    record_index: int = field()
    opcode_offset: int = field()


@dataclass(frozen=True, slots=True)
class SemanticIrDocument(AnalysisDocument, SemanticDocument):
    """Existing S3 semantic text plus evidence traceability."""

    text: str = field()
    source_map: tuple[SemanticSourceReference, ...]
    diagnostics: tuple[Diagnostic, ...] = ()
    plugin_id: str = field(default=S3_BOOT_SCRIPT_PLUGIN_ID, init=False)

    def source_for_line(self, line: int) -> SemanticSourceReference:
        """Return the binary source for a one-based semantic line."""
        if line < 1 or line > len(self.source_map):
            raise IndexError(f"Semantic line {line} is outside the document")
        return self.source_map[line - 1]


class SemanticIrBuilder:
    """Project raw S3 records into the existing semantic IR language."""

    def build(self, raw_script: RawBootScript) -> SemanticIrDocument:
        """Build semantic text and its source map in record order."""
        statements = tuple(_semantic_statements(raw_script.records))
        return SemanticIrDocument(
            text=_render_document_text(statements),
            source_map=_build_source_map(statements),
        )


@dataclass(frozen=True)
class _SemanticStatement:
    text: str
    record_index: int
    opcode_offset: int


def semantic_annotation(record: RawOpcodeRecord) -> str | None:
    """Return the unresolved semantic template for a raw record."""
    return SEMANTIC_ANNOTATIONS.get(get_opcode_mnemonic(record.opcode_id))


def _semantic_statements(records: list[RawOpcodeRecord]) -> list[_SemanticStatement]:
    statements: list[_SemanticStatement] = []
    for record_index, record in enumerate(records):
        rendered = _render_semantic_record(record)
        if rendered is not None:
            statements.append(_SemanticStatement(rendered, record_index, record.offset))
    return statements


def _render_semantic_record(record: RawOpcodeRecord) -> str | None:
    template = semantic_annotation(record)
    if template is None:
        return None
    return _resolve_semantic_fields(record, template)


def _resolve_semantic_fields(record: RawOpcodeRecord, template: str) -> str:
    rendered = template
    semantic_fields = _semantic_fields(record)
    for field_name in sorted(semantic_fields, key=len, reverse=True):
        rendered = rendered.replace(field_name, semantic_fields[field_name])
    return rendered


def _semantic_fields(record: RawOpcodeRecord) -> dict[str, str]:
    return {
        field_name: format_semantic_value(getattr(record.body, field_name, MISSING_FIELD_TEXT))
        for field_name in get_opcode_fields(record.opcode_id)
    }


def _render_document_text(statements: tuple[_SemanticStatement, ...]) -> str:
    return LINE_SEPARATOR.join(statement.text for statement in statements) + LINE_SEPARATOR


def _build_source_map(
    statements: tuple[_SemanticStatement, ...],
) -> tuple[SemanticSourceReference, ...]:
    return tuple(
        SemanticSourceReference(
            semantic_line=line_number,
            record_index=statement.record_index,
            opcode_offset=statement.opcode_offset,
        )
        for line_number, statement in enumerate(statements, start=1)
    )
