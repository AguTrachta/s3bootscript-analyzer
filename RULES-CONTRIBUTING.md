# Writing and contributing analysis rules

An analyzer rule is a YAML document selected with `s3bootscript-analyzer analyze
--rule PATH`. It combines a structural match over the S3 semantic representation
with an optional Boolean condition. The rule declares its own severity; a match
is a finding under that rule, not proof that the binary is compromised.

Rules are analyzer documents, not standalone ast-grep rule files. The current
rule document format uses `schema_version: 1` and `plugin: s3bootscript`.

## How to find the available data

1. Run `disassemble --output-format semantic` on a representative binary to see
   the exact text that `matcher.config.rule.pattern` can match. The semantic
   representation is a view of decoded records, not the complete record data.
2. Use the [S3 record field reference](#s3-record-field-reference) below for
   `record` keys and their types in conditions. `disassemble --output-format
   json` is for presentation: it formats values as strings and does not expose
   the condition context verbatim.
3. Read the JSON profile selected with `--profile` for its producer-defined
   fields. The analyzer imposes no S3-specific profile schema or meaning on
   labels. A rule should name any top-level fields it needs in
   `profile.required_fields`.

For example, the repository sample contains this semantic line for a record at
byte offset `0x24`:

```text
mem[0xd0b30000] <- 0x0001
```

Its condition context contains `record["fields"]["width"] == 1`,
`record["fields"]["count"] == 1`, `record["fields"]["address"] == 0xd0b30000`,
and `record["fields"]["buffer"] == (1, 0)`. Here `width` is the encoded width
code, and `buffer` is a sequence of bytes. The rendered value `0x0001` does not
carry the count or describe every effective destination.

## Complete rule example

This example identifies a `MEM_WRITE` with encoded 16-bit width and count one.
It is informational: those facts alone do not establish a security risk.

```yaml
schema_version: 1
plugin: s3bootscript
metadata:
  id: S3-MEM-WRITE-WIDTH-EXAMPLE
  title: Memory write with one 16-bit element
  description: Demonstrates matching semantic text and checking original record fields.
  severity: informational
matcher:
  type: ast_grep
  config:
    language: s3boot
    rule:
      pattern: mem[$ADDR] <- $VALUE
condition:
  language: simpleeval
  expression: >-
    record["fields"]["width"] == 1 and
    record["fields"]["count"] == 1
```

Save the YAML as `my-rule.yaml`, then run:

```bash
nix develop -c s3bootscript-analyzer disassemble \
  --input-binary samples/binaries/s3bootscript.bin \
  --output-format semantic

nix develop -c s3bootscript-analyzer analyze \
  --input-binary samples/binaries/s3bootscript.bin \
  --rule my-rule.yaml \
  --output-format markdown
```

The matcher selects semantic lines first. `$ADDR` and `$VALUE` become capture
names in the condition. Hexadecimal and decimal captures are converted to
integers; other captures remain strings. The S3 plugin then joins each match to
its binary record by record identity and provides its facts as `record`.
`profile` and `record` are reserved names and cannot be capture names.

The required YAML sections are `schema_version`, `plugin`, `metadata`, and
`matcher`. `metadata` needs `id`, `title`, and one of the severities `safe`,
`informational`, `warning`, or `critical`. `condition` and `profile` are
optional. `matcher.config` contains the native ast-grep rule configuration;
its `language` is `s3boot`. The rule loader checks the document structure and
plugin compatibility, but it does not check whether a `record` field name is
valid for the opcode selected by the pattern.

## S3 record field reference

The S3 plugin supplies the following read-only keys for each matched record:

| Expression | Type | Meaning |
| --- | --- | --- |
| `record["record_index"]` | integer | Zero-based index among parsed opcode records; the table header is excluded. |
| `record["offset"]` | integer | Byte offset in the input file, not a physical address. |
| `record["opcode_id"]` | integer | Numeric opcode value. |
| `record["opcode"]` | string | Opcode mnemonic, such as `MEM_WRITE`. |
| `record["length"]` | integer | Serialized record length in bytes, including its prefix. |
| `record["raw_bytes"]` | sequence of integers | Full serialized record bytes, each from 0 to 255. |
| `record["fields"]` | mapping | Decoded fields listed below for that opcode. |

Within `record["fields"]`, `buffer`, `data`, `data_mask`, and
`information_data` are read-only sequences of byte values. All other listed
fields are integers for binaries decoded by the current Kaitai parser. A field
not listed for an opcode is absent; it is not `null` or zero.

| Opcode | Fields in `record["fields"]` |
| --- | --- |
| `IO_WRITE`, `MEM_WRITE`, `PCI_CONFIG_WRITE` | `width`, `count`, `address`, `buffer` |
| `PCI_CONFIG2_WRITE` | `width`, `count`, `address`, `segment`, `buffer` |
| `IO_READ_WRITE`, `MEM_READ_WRITE`, `PCI_CONFIG_READ_WRITE` | `width`, `address`, `data`, `data_mask` |
| `PCI_CONFIG2_READ_WRITE` | `width`, `address`, `segment`, `data`, `data_mask` |
| `IO_POLL`, `PCI_CONFIG_POLL` | `width`, `address`, `delay`, `data`, `data_mask` |
| `MEM_POLL` | `width`, `address`, `duration`, `loop_times`, `data`, `data_mask` |
| `PCI_CONFIG2_POLL` | `width`, `address`, `segment`, `delay`, `data`, `data_mask` |
| `SMBUS_EXECUTE` | `sm_bus_address`, `operation`, `data_size`, `buffer` |
| `STALL` | `duration` |
| `DISPATCH` | `entry_point` |
| `DISPATCH_2` | `entry_point`, `context` |
| `INFORMATION` | `information_length`, `information_data` |
| `TERMINATE` | No decoded fields. |

The width codes defined by the current binary schema are `0`–`3` for normal
8-, 16-, 32-, and 64-bit accesses, `4`–`7` for FIFO widths, and `8`–`11` for
FILL widths. `width` is the encoded code, not a byte count. The fields are
original serialized values; they are not validated effective write intervals
or PCI coordinates. `address` has an opcode-dependent meaning and must not be
treated as a physical memory address for every opcode. The packed
`sm_bus_address` is not split into subfields in this contract.

The document retains records with no semantic line, including `TERMINATE` and
unknown opcodes, but the current ast-grep matcher cannot select them through
semantic text. Unknown opcodes have no named decoded fields. The rule document
`schema_version` versions the YAML format; it does not separately version this
S3 field reference.

## Conditions, profiles, and results

A condition evaluates one candidate at a time. It can use numeric captures,
`record`, and the selected producer's `profile` data. It must return a Boolean.
For example, a rule with `profile.required_fields: [ranges]` can compare a
captured address with the producer's `profile["ranges"]` using an expression
such as:

```text
any([region["start"] <= ADDR <= region["end"]
     for region in profile["ranges"]])
```

See the [kernel-write rule](rules/base/kernel-write.rule.yaml) and its
[synthetic profile](profiles/examples/kernel.profile.json) for a complete
profile-based example. A synthetic profile demonstrates the format; it is not
evidence about the platform that produced a different binary.

`profile.required_fields` checks only literal top-level JSON keys. If a
declared field is absent, that rule returns `unknown`. An invalid explicitly
selected profile is a setup error. A missing nested profile key, a missing
`record` field for a candidate, or an invalid expression produces a rule
`error`. A condition is evaluated only when the matcher returns a candidate:
with no candidate, a misspelled field access may remain untested and the rule
can return `not_matched`. Always exercise a new rule on at least one known
matching input and one case it should reject.

The report lists the rule's declared severity separately from its outcome.
`not_matched` means the rule found no accepted candidate in that run; it is
not a safety verdict. Reports show captures and binary locations, but do not
currently print the complete `record` context. The current analysis also does
not establish execution coverage, derive complete write effects, or infer
trusted memory from a producer's labels.

Before contributing a rule, verify its semantic pattern against the selected
opcode, state which profile facts it requires, justify its severity, and check
positive, negative, and insufficient-data cases where relevant. Keep
platform-specific policy in the rule and producer profile rather than relying
on a generic interpretation of addresses or labels.
