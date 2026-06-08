# s3bootscript-analyzer

`s3bootscript-analyzer` is a Python tool for inspecting UEFI S3 Boot Script
binaries. It parses a raw boot script table, decodes the opcodes into a readable
intermediate representation, and can generate platform memory profiles that are
useful for later rule-based security analysis.

The project is thesis-oriented and focuses on detecting risky S3 resume behavior,
such as writes to sensitive memory-mapped regions, unsafe dispatch targets, and
platform-specific address ranges that need manual review.

## What It Does

- Reads a raw S3 Boot Script binary.
- Parses the table header and opcode records.
- Decodes known opcodes into text, semantic text, or JSON.
- Keeps unknown opcodes visible instead of silently dropping them.
- Generates `/proc/iomem`-based platform profiles as JSON.
- Supports a kernel-only `/proc/iomem` profile with normalized range names.

## Requirements

- Python 3.12
- Poetry
- GNU/Linux for `/proc/iomem` profile generation

Install dependencies:

```bash
poetry install --no-interaction
```

## Disassemble A Boot Script

Print a readable text representation:

```bash
poetry run s3bootscript-analyzer \
  --input-binary samples/binaries/s3bootscript.bin
```

Write JSON output:

```bash
poetry run s3bootscript-analyzer \
  --input-binary samples/binaries/s3bootscript.bin \
  --output-format json \
  --output-report /tmp/s3bootscript.json
```

Print semantic IR:

```bash
poetry run s3bootscript-analyzer \
  --input-binary samples/binaries/s3bootscript.bin \
  --output-format semantic
```

Semantic output is intended to be easier to match with rule tools. For example:

```text
mem[0xfed15418] <- 0x24
poll until (mem[0xfde00000] & 0x800f3210) == 0x800f3210
call 0x12345678
```

## Generate Platform Profiles

The analyzer can generate JSON profiles from Linux `/proc/iomem`. These profiles
describe memory ranges that later analysis can use to decide whether an opcode
targets OS-controlled memory, firmware-related memory, MMIO, or unknown regions.

Generate a general `/proc/iomem` profile:

```bash
poetry run s3bootscript-analyzer \
  --generate-profile proc-iomem \
  --profile-output /tmp/proc-iomem-profile.json
```

Generate a kernel-only profile:

```bash
poetry run s3bootscript-analyzer \
  --generate-profile kernel \
  --profile-output /tmp/proc-iomem-kernel-profile.json
```

Profile generation reads `/proc/iomem`, so it may require `sudo` depending on the
system configuration.

## Profile JSON Shape

Generated profiles use this structure:

```json
{
  "source": "proc_iomem",
  "ranges": {
    "os_controlled": [],
    "firmware_related": [],
    "mmio_related": [],
    "unknown": []
  },
  "diagnostics": [],
  "schema_version": 1
}
```

The kernel-only profile keeps the same schema but maps kernel labels to stable
names:

```json
{
  "name": "KERNEL_CODE_RANGE",
  "start": 9201803264,
  "end": 9227046911,
  "source_label": "Kernel code"
}
```

Diagnostics are warnings about profile generation itself, such as malformed input
lines or missing matching ranges. They are not security findings.

## Current Scope

This project currently covers parsing, decoding, rendering, and profile
generation. Rule evaluation and final report generation are expected to build on
top of the decoded IR and generated profiles.
