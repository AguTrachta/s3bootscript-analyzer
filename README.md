# s3bootscript-analyzer

A Python 3.12 tool for inspecting UEFI S3 Boot Script binaries. It parses binary
records, renders decoded opcodes, and generates Linux platform profiles. The
Python API also provides declarative rule loading and analysis orchestration.

The command-line interface supports disassembly and profile generation.
It does not currently execute security rules or produce Markdown/HTML analysis
reports.

## Requirements

- Python 3.12
- Nix with flakes enabled for the reproducible development environment
- GNU/Linux for profile generation from `/proc/iomem`

Enter the development environment:

```bash
nix develop
```

## Disassemble a binary

Print decoded opcodes:

```bash
nix develop -c s3bootscript-analyzer \
  --input-binary samples/binaries/s3bootscript.bin
```

Write JSON output:

```bash
nix develop -c s3bootscript-analyzer \
  --input-binary samples/binaries/s3bootscript.bin \
  --output-format json \
  --output-report /tmp/s3bootscript.json
```

Print semantic IR:

```bash
nix develop -c s3bootscript-analyzer \
  --input-binary samples/binaries/s3bootscript.bin \
  --output-format semantic
```

Semantic output represents operations in a syntax suitable for structural
matching, for example:

```text
mem[0xfed010a8] <- 0x00000000
poll until (mem[0xfed01004] & 0x0020) == 0x0000
```

The semantic document retains a source map linking emitted lines to record
indexes and binary offsets. Unknown opcodes remain visible in ordinary text and
JSON output; records without semantic annotations are omitted from semantic IR.

Use `--verbose` to include opcode metadata in text output, and `--debug` for
diagnostic logging to standard error. Supported output formats are `text`,
`json`, and `semantic`.

## Generate a profile

Generate selected memory ranges from Linux `/proc/iomem`:

```bash
nix develop -c s3bootscript-analyzer \
  --generate-profile proc-iomem \
  --profile-output /tmp/platform.json
```

Generate only kernel ranges:

```bash
nix develop -c s3bootscript-analyzer \
  --generate-profile kernel \
  --profile-output /tmp/kernel.json
```

The source readers invoke `sudo` to read `/proc/iomem`. Without
`--profile-output`, the generated JSON is printed to standard output.

Generated profiles contain `source`, `ranges`, `diagnostics`, and
`schema_version`. Each range includes its name, inclusive numeric boundaries,
and original source label. The kernel generator uses names such as
`KERNEL_CODE_RANGE` and `KERNEL_DATA_RANGE`.

Generation diagnostics describe collection problems; they are not security
findings. Profile contents must correspond to the system being analyzed.

## Load profile data in Python

The JSON loader consumes generated files directly. It also accepts JSON objects
from other producers, including nested limits, identifiers, strings, and flags.

From the development environment:

```python
from pathlib import Path

from s3bootscript_analyzer.analysis import ProfileSelection
from s3bootscript_analyzer.profile_data import JsonProfileLoader

profile = JsonProfileLoader().load(
    ProfileSelection(path=Path("profiles/examples/kernel.profile.json"))
)
profile.require_fields(("ranges",))
print(profile.name)
print(profile.data["ranges"])
```

The loader preserves field names and values, freezes objects and arrays into
read-only mappings and tuples, and uses the filename for reporting. It rejects
invalid JSON, duplicate keys, non-finite numbers, excessive nesting, and a
non-object root. An invalid explicit file raises `ProfileLoadError`.
Selecting no file produces an empty default profile.

The shared profile contract has no required memory fields or security
classifications. Producers define their data; rule expressions select and
interpret those facts.

## Analysis API

The Python API includes:

- Safe YAML rule loading with schema and plugin validation.
- A trusted plugin catalog and S3 plugin facade.
- Generic `profile.required_fields` checks for literal top-level JSON keys.
- Per-rule outcomes: `matched`, `not_matched`, `unknown`, `error`, and `skipped`.
- ast-grep JSON-stream decoding with numeric captures and binary traceability.
- An `AnalyzeArtifact` use case returning structured `AnalysisReport` values.

`AstGrepMatcher` now provides structural matching through the Python API.
The quality gate compiles its checked-in grammar before running the matcher tests;
run it once before using the matcher directly.
The simpleeval evaluator and analysis CLI remain pending; no new CLI flags are available.
Rules in `rules/base/` are analyzer rule documents; they are not native ast-grep
rule files and are not executed by the disassembly command.

## Development checks

```bash
nix develop -c scripts/quality-gate
nix develop -c scripts/repository-content-check
```

The checks cover parser regeneration, linting, formatting, strict typing,
security checks, cyclomatic complexity, tests, rule schemas, profile examples,
and repository content.

## License

MIT.
