# s3bootscript-analyzer

A Python 3.12 tool for inspecting UEFI S3 Boot Script binaries. It decodes
opcodes, evaluates declarative rules against platform profile data, and produces
Markdown or HTML reports with findings, diagnostics, and binary locations.
The CLI also supports disassembly and Linux profile generation.

## Requirements

- Python 3.12
- Nix with flakes enabled for the reproducible development environment
- GNU/Linux for profile generation from `/proc/iomem`

Before first use, install `git-lfs` and pull the sample binaries:

```bash
sudo apt-get install -y git-lfs
git lfs install --skip-repo
git lfs pull
```

Then enter the development environment:

```bash
nix develop
```

`--generate-profile proc-iomem`/`kernel` prompts for your `sudo` password
interactively when it runs.

## Analyze a binary

Generate a Markdown report using a rule and a JSON profile:

```bash
nix develop -c s3bootscript-analyzer analyze \
  --input-binary samples/binaries/s3bootscript.bin \
  --rule rules/base/kernel-write.rule.yaml \
  --profile profiles/examples/kernel.profile.json \
  --output-format markdown \
  --output-report /tmp/analysis.md
```

The example profile contains synthetic addresses. It demonstrates the input
format and may produce no matches for the sample binary. For platform analysis,
use profile facts collected for the system that produced the binary.

To generate HTML, use `--output-format html --output-report /tmp/analysis.html`.
Markdown is the default format. Omit `--output-report` to print the report to
standard output.

| Option | Purpose |
| --- | --- |
| `--input-binary PATH` | Required binary input |
| `--rule PATH` | Required rule file; repeat to evaluate additional files in order |
| `--profile PATH` | Optional JSON profile; omission uses empty facts |
| `--output-format markdown\|html` | Report format; defaults to Markdown |
| `--output-report PATH` | Output file; defaults to standard output |
| `--debug` | Send debug diagnostics to standard error |
| `--quiet` | Suppress informational output while retaining errors and the report |

`--debug` and `--quiet` are mutually exclusive. Run
`s3bootscript-analyzer analyze --help` for the full command help.

Reports list every evaluated rule with its declared severity and separate
outcome: `matched`, `not_matched`, `unknown`, `error`, or `skipped`. Evidence
includes captured values, semantic text, record indexes, and binary byte
offsets. Missing required profile data produces `unknown`; an invalid selected
profile is an error. A rule failure can appear alongside findings from other
rules in the same report.

| Exit code | Meaning |
| --- | --- |
| `0` | Completed without matches; may include unknown or skipped rules |
| `3` | One or more rules matched |
| `1` | Operational failure, even if another rule matched |
| `2` | Invalid command arguments |

A match reflects the rule's condition and declared severity. An exit code of
`0` is not a safety verdict. Setup or output failures may prevent report creation.

Analysis rules currently match semantic IR generated from the binary. The text
and JSON disassembly formats below do not select a different rule input.

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
- `SimpleEvalConditionEvaluator` for Boolean conditions over captures and generic
  `profile` facts, including comprehensions with `any`.
- An `AnalyzeArtifact` use case returning structured `AnalysisReport` values.

Custom Python adapters must inherit their abstract base class contracts and
implement the declared abstract operations.

`AstGrepMatcher` provides structural matching through the CLI and Python API.
`nix develop` builds its grammar automatically.
Conditions must return a Boolean; invalid expressions and evaluation failures
become rule errors. Each candidate uses isolated captures, and `profile` is reserved.
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
