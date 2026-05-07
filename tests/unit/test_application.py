from pathlib import Path

from s3bootscript_analyzer.application import (
    APPLICATION_NAME,
    APPLICATION_STATUS_READY,
    BootScriptDisassembler,
    get_application_info,
)
from s3bootscript_analyzer.engine import build_default_opcode_decoder
from s3bootscript_analyzer.ingest import BinarySource, FileLoader
from s3bootscript_analyzer.parsers.raw import RawBootScript, RawOpcodeRecord, RawTableHeader
from s3bootscript_analyzer.reporting import TextIrRenderer


class StaticRawParser:
    def parse(self, source: BinarySource) -> RawBootScript:
        return RawBootScript(
            table_header=RawTableHeader(
                magic=HEADER_MAGIC,
                length=HEADER_LENGTH,
                version=HEADER_VERSION,
                table_length=source.size(),
            ),
            records=[
                RawOpcodeRecord(
                    opcode_id=STALL_OPCODE_ID,
                    length=STALL_RECORD_LENGTH,
                    offset=HEADER_LENGTH,
                    body=StallBody(duration=STALL_DURATION),
                    raw_bytes=STALL_RAW_BYTES,
                )
            ],
        )


class StallBody:
    def __init__(self, duration: int) -> None:
        self.duration = duration


HEADER_MAGIC = 0xAA
HEADER_LENGTH = 13
HEADER_VERSION = 1
STALL_OPCODE_ID = 0x07
STALL_RECORD_LENGTH = 11
STALL_DURATION = 100
STALL_RAW_BYTES = bytes.fromhex("07000b6400000000000000")


def test_get_application_info_returns_scaffold_metadata() -> None:
    application_info = get_application_info()

    assert application_info.name == APPLICATION_NAME
    assert application_info.status == APPLICATION_STATUS_READY


def test_disassembler_decodes_text_ir(tmp_path: Path) -> None:
    input_path = tmp_path / "boot-script.bin"
    input_path.write_bytes(STALL_RAW_BYTES)
    disassembler = BootScriptDisassembler(
        file_loader=FileLoader(),
        raw_parser=StaticRawParser(),
        opcode_decoder=build_default_opcode_decoder(),
        renderer=TextIrRenderer(),
    )

    text_ir = disassembler.execute(input_path)

    assert "BOOT_SCRIPT_TABLE" in text_ir
    assert "STALL" in text_ir
    assert "duration=0x64" in text_ir
