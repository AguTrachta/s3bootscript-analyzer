"""Static FACS facts collected from Linux ACPI table files."""

from __future__ import annotations

import subprocess  # nosec B404
from dataclasses import dataclass, field
from pathlib import Path
from struct import unpack_from

from s3bootscript_analyzer.errors import BootScriptAnalyzerError
from s3bootscript_analyzer.profile_data.commands import CommandSpec, SubprocessRunner
from s3bootscript_analyzer.profile_data.contracts import ProfileLoader
from s3bootscript_analyzer.profile_data.models import PlatformProfile

DEFAULT_FADT_PATH = Path("/sys/firmware/acpi/tables/FACP")
DEFAULT_FACS_PATH = Path("/sys/firmware/acpi/tables/FACS")

FADT_MIN_LENGTH = 116
FADT_FIRMWARE_CTRL_OFFSET = 0x24
FADT_X_FIRMWARE_CTRL_OFFSET = 0x84
FACS_MIN_LENGTH = 64
FACS_ALIGNMENT = 64
FACS_LEGACY_VECTOR_OFFSET = 0x0C
FACS_EXTENDED_VECTOR_OFFSET = 0x18
LEGACY_VECTOR_SIZE = 4
EXTENDED_VECTOR_SIZE = 8


class FacsProfileError(BootScriptAnalyzerError):
    """Raised when static FADT/FACS facts cannot be collected reliably."""


@dataclass(frozen=True)
class FacsAddressRange:
    """Inclusive physical address range of a FACS field."""

    start: int
    end: int


@dataclass(frozen=True)
class FacsPointerFields:
    """Raw FADT pointers to the FACS table."""

    firmware_ctrl: int
    x_firmware_ctrl: int


@dataclass(frozen=True)
class FacsMetadata:
    """Static FACS header metadata that does not contain waking vector values."""

    hardware_signature: int
    flags: int
    version: int


@dataclass(frozen=True)
class FacsProvenance:
    """Source paths used to collect the ACPI tables."""

    fadt_source: str
    facs_source: str


@dataclass(frozen=True)
class FacsData:
    """Validated, static FACS facts for declarative rules."""

    physical_address: int
    length: int
    signature: str
    pointer_source: str
    fadt_pointers: FacsPointerFields
    legacy_waking_vector: FacsAddressRange
    extended_waking_vector: FacsAddressRange
    metadata: FacsMetadata
    collection_complete: bool
    provenance: FacsProvenance


@dataclass(frozen=True)
class FacsProfile(PlatformProfile):
    """Producer-specific profile with a top-level FACS object."""

    facs: FacsData = field(kw_only=True)


@dataclass(frozen=True)
class _FadtLocation:
    physical_address: int
    pointer_source: str
    pointers: FacsPointerFields


class FacsProfileLoader(ProfileLoader):
    """Load static ACPI table facts without observing an S3 transition."""

    def __init__(
        self,
        fadt_path: Path = DEFAULT_FADT_PATH,
        facs_path: Path = DEFAULT_FACS_PATH,
        runner: SubprocessRunner | None = None,
    ) -> None:
        self._fadt_path = fadt_path
        self._facs_path = facs_path
        self._runner = runner if runner is not None else SubprocessRunner()

    def load(self) -> FacsProfile:
        fadt = _read_table(self._fadt_path, self._runner)
        facs = _read_table(self._facs_path, self._runner)
        location = _parse_fadt_location(fadt)
        facs_length = _validate_facs(facs, location.physical_address)
        base = location.physical_address
        return FacsProfile(
            source="acpi_facs",
            facs=FacsData(
                physical_address=base,
                length=facs_length,
                signature="FACS",
                pointer_source=location.pointer_source,
                fadt_pointers=location.pointers,
                legacy_waking_vector=_field_range(
                    base, FACS_LEGACY_VECTOR_OFFSET, LEGACY_VECTOR_SIZE
                ),
                extended_waking_vector=_field_range(
                    base, FACS_EXTENDED_VECTOR_OFFSET, EXTENDED_VECTOR_SIZE
                ),
                metadata=FacsMetadata(
                    hardware_signature=unpack_from("<I", facs, 8)[0],
                    flags=unpack_from("<I", facs, 0x14)[0],
                    version=facs[0x20],
                ),
                collection_complete=True,
                provenance=FacsProvenance(str(self._fadt_path), str(self._facs_path)),
            ),
        )


def _read_table(path: Path, runner: SubprocessRunner) -> bytes:
    try:
        return path.read_bytes()
    except PermissionError:
        return _read_protected_table(path, runner)
    except OSError as ex:
        raise FacsProfileError(f"Unable to read ACPI table '{path}': {ex}") from ex


def _read_protected_table(path: Path, runner: SubprocessRunner) -> bytes:
    try:
        result = runner.run(CommandSpec(argv=["cat", str(path)], sudo=True, capture_output=True))
    except (OSError, subprocess.CalledProcessError) as ex:
        raise FacsProfileError(f"Unable to read ACPI table '{path}' with sudo: {ex}") from ex
    return result.stdout


def _parse_fadt_location(fadt: bytes) -> _FadtLocation:
    length = _validate_fadt(fadt)
    firmware_ctrl = unpack_from("<I", fadt, FADT_FIRMWARE_CTRL_OFFSET)[0]
    x_firmware_ctrl = _extended_pointer(fadt, length)
    physical_address = x_firmware_ctrl or firmware_ctrl
    if physical_address == 0:
        raise FacsProfileError("FADT (FACP) contains no usable FACS pointer")
    pointer_source = "X_FIRMWARE_CTRL" if x_firmware_ctrl else "FIRMWARE_CTRL"
    return _FadtLocation(
        physical_address,
        pointer_source,
        FacsPointerFields(firmware_ctrl, x_firmware_ctrl),
    )


def _validate_fadt(fadt: bytes) -> int:
    _require_fadt_signature(fadt)
    length = int(unpack_from("<I", fadt, 4)[0])
    if not FADT_MIN_LENGTH <= length <= len(fadt):
        raise FacsProfileError("Invalid FADT (FACP) length")
    if sum(fadt[:length]) % 256 != 0:
        raise FacsProfileError("Invalid FADT (FACP) checksum")
    return length


def _require_fadt_signature(fadt: bytes) -> None:
    if len(fadt) < FADT_MIN_LENGTH:
        raise FacsProfileError("Truncated FADT (FACP) table")
    if fadt[:4] != b"FACP":
        raise FacsProfileError("Invalid FADT (FACP) signature")


def _extended_pointer(fadt: bytes, declared_length: int) -> int:
    if declared_length < FADT_X_FIRMWARE_CTRL_OFFSET + 8:
        return 0
    return int(unpack_from("<Q", fadt, FADT_X_FIRMWARE_CTRL_OFFSET)[0])


def _validate_facs(facs: bytes, physical_address: int) -> int:
    _require_facs_signature(facs)
    length = int(unpack_from("<I", facs, 4)[0])
    if not FACS_MIN_LENGTH <= length <= len(facs):
        raise FacsProfileError("Invalid FACS length")
    _validate_facs_address(physical_address, length)
    return length


def _require_facs_signature(facs: bytes) -> None:
    if len(facs) < FACS_MIN_LENGTH:
        raise FacsProfileError("Truncated FACS table")
    if facs[:4] != b"FACS":
        raise FacsProfileError("Invalid FACS signature")


def _validate_facs_address(physical_address: int, length: int) -> None:
    if physical_address % FACS_ALIGNMENT != 0:
        raise FacsProfileError("FACS physical address is not 64-byte aligned")
    if physical_address > (1 << 64) - length:
        raise FacsProfileError("FACS physical address range exceeds 64 bits")


def _field_range(base: int, offset: int, size: int) -> FacsAddressRange:
    return FacsAddressRange(base + offset, base + offset + size - 1)
