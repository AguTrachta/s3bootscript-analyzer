"""Opcode identifiers from the Kaitai schema."""

from __future__ import annotations

from enum import IntEnum


class OpcodeId(IntEnum):
    """Supported UEFI S3 boot script opcode identifiers."""

    IO_WRITE = 0x00
    IO_READ_WRITE = 0x01
    MEM_WRITE = 0x02
    MEM_READ_WRITE = 0x03
    PCI_CONFIG_WRITE = 0x04
    PCI_CONFIG_READ_WRITE = 0x05
    SMBUS_EXECUTE = 0x06
    STALL = 0x07
    DISPATCH = 0x08
    DISPATCH_2 = 0x09
    INFORMATION = 0x0A
    PCI_CONFIG2_WRITE = 0x0B
    PCI_CONFIG2_READ_WRITE = 0x0C
    IO_POLL = 0x0D
    MEM_POLL = 0x0E
    PCI_CONFIG_POLL = 0x0F
    PCI_CONFIG2_POLL = 0x10
    HEADER = 0xAA
    TERMINATE = 0xFF
