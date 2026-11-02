# Testing guide

Run the existing checks from the supported Python 3.12 environment:

```bash
nix develop -c scripts/quality-gate
```

This guide establishes the shared foundation for [#38](https://github.com/AguTrachta/s3bootscript-analyzer/issues/38).
It does not claim that the downstream acceptance expansion, properties, coverage
reports, or mutation pilot have been implemented.

## Choose the smallest useful boundary

Follow Vladimir Khorikov's *Unit Testing: Principles, Practices, and Patterns*:
protect meaningful behavior while balancing regression protection, resistance to
refactoring, fast feedback, and maintainability. Prefer public results and
observable effects over private helpers and incidental internal call sequences.
Use doubles at meaningful external boundaries, not for every collaboration.

Keep tests independent, with Arrange, Act, Assert and one coherent behavior per
test. Parametrize distinct scenarios with explicit expected results instead of
branching assertions. Add tests for distinct requirements, not numerical targets.
For behavioral changes with a meaningful runnable test, observe RED before the
fix, then GREEN and refactor. Documentation/configuration-only changes instead
need structural checks, configuration loading, and compatibility verification;
do not manufacture failing tests for third-party tools.

| Boundary | What it proves | Current examples |
| --- | --- | --- |
| Focused behavioral test | A public responsibility, with isolated external collaborators where useful | `tests/unit/` |
| Injected CLI integration | In-process `main()` behavior with selected collaborators replaced | `tests/integration/test_cli_analysis.py` replaces the renderer |
| Composed integration | Real parsing/matching/rendering, still calling `main()` in process | `tests/integration/test_report_cli.py`, `test_real_sample.py` |
| Development-install subprocess | Real console process with production collaborators in the development environment | `tests/acceptance/test_cli_e2e.py` |
| Packaged-artifact acceptance | Explicit built executable and declared runtime resources, without checkout fallbacks | Not established by the current subprocess tests; follow-up #39 |

Directory names alone do not establish a boundary. CI currently uses an editable
Nix development environment; a command resolved from PATH is not proof of an
isolated package installation. Record the executable path and installation mode.

## Current CLI contract matrix

This inventory describes the source at foundation revision `0566bf9`. Test names
below identify existing protection, not an assertion that every stream/file effect
is checked. Reconcile this table when behavior or tests change.

Paths in the test column are relative to `tests/`. `I` means
`integration/test_cli_analysis.py`, `R` means `integration/test_report_cli.py`,
`U` means `unit/test_cli.py`, and `A` means `acceptance/test_cli_e2e.py`.

| Command / scenario | Exit | Output contract | Existing test ID | Gap / follow-up |
| --- | --- | --- | --- | --- |
| Root help / missing command | 0 / 2 | Help on stdout; argument errors on stderr; no report | U: `test_main_help_lists_all_operations`, `test_main_requires_a_command` | Subcommand process help/validation: #39 |
| Analyze: findings, stdout | 3 | Markdown default or HTML report on stdout | A: `test_installed_command_prints_profile_filtered_report`; R: `test_real_binary_report_contains_only_profile_accepted_evidence` | A does not assert stderr: #39 |
| Analyze: findings, file | 3 | Report file; stdout empty | A: `test_installed_command_writes_profile_filtered_report_to_file` | A does not assert stderr: #39 |
| Analyze: no match | 0 | Requested report, not a safety verdict | I: `test_no_matching_writes_returns_success`; R: `test_no_match_is_reported_with_the_rules_declared_warning_severity` | No subprocess story: #39 |
| Analyze: missing required profile facts | 0 | Report includes unknown, not invented facts | I: `test_omitted_profile_is_empty_and_missing_declared_facts_remain_unknown`; R: `test_missing_profile_facts_are_reported_as_unknown_with_a_reason` | No subprocess story: #39 |
| Analyze: disabled rule | 0 | Report includes skipped | R: `test_disabled_rule_remains_visible_as_skipped` | In-process protection; retain |
| Analyze: unreadable input / invalid selected profile | 1 | Operational diagnostic on stderr; setup can prevent report creation | I: `test_unreadable_input_reports_the_path_on_stderr`, `test_invalid_selected_profile_is_an_error_without_default_fallback` | No subprocess story: #39 |
| Analyze: invalid arguments | 2 | Usage diagnostic on stderr; no analysis | I: `test_invalid_invocation_reports_the_specific_usage_error` | No subprocess story: #39 |
| Analyze: output failure, even with finding | 1 | Output diagnostic on stderr; do not assume atomic writes | I: `test_output_failure_takes_precedence_over_a_match` | Injected renderer; process failure case: #39 |
| Analyze: rule error alongside finding | 1 | Report preserves finding; error diagnostics remain visible | R: `test_invalid_rule_diagnostic_and_valid_finding_share_the_report`; I: `test_condition_error_preserves_later_finding_and_returns_failure` | Process error precedence: #39 |
| Analyze: debug / quiet | Result-dependent; conflict 2 | Debug to stderr; report and errors retained under quiet | I: `test_debug_keeps_diagnostics_on_stderr_and_report_on_stdout`, `test_quiet_retains_requested_report_without_informational_output`, `test_quiet_retains_operational_errors` | Do not redefine quiet as silence |
| Disassemble: text / JSON / semantic | 0 | Selected format on stdout; default text | `integration/test_real_sample.py`: `test_cli_text_output_for_real_sample`, `test_cli_json_output_for_real_sample`, `test_cli_semantic_output_matches_stable_golden` | No subprocess story: #39 |
| Disassemble: file output | 0 | Selected output file instead of stdout | U: `test_main_writes_output_to_file` | Injected disassembler; no subprocess story: #39 |
| Disassemble: handled failure / invalid format | 1 / 2 | Handled error on stdout; argument errors on stderr; debug on stderr | U: `test_main_reports_missing_input`, `test_main_rejects_invalid_output_format`, `test_main_accepts_debug_and_writes_diagnostics_to_stderr` | No subprocess story: #39 |
| Generate-profile: proc-iomem / kernel success | 0 | JSON on stdout or profile-output file | U: `test_main_generates_proc_iomem_profile_to_stdout`, `test_main_generates_proc_iomem_profile_to_file`, `test_main_generates_kernel_iomem_profile_to_stdout`, `test_main_generates_kernel_iomem_profile_to_file` | Injected source; not real host acceptance |
| Generate-profile: handled proc-iomem / kernel failure | 1 | Handled source/output diagnostic on stdout | `unit/test_profile_data.py`: `test_subprocess_runner_rejects_unexpected_return_code` protects runner rejection, not CLI exit/streams | CLI failure routing remains a gap: #39 |
| Generate-profile: facs success / missing tables | 0 / 1 | JSON on stdout or profile-output file; handled errors on stdout | `unit/test_facs_profile.py`: `test_facs_cli_generates_profile_from_acpi_tables`, `test_facs_cli_reports_missing_table_instead_of_empty_profile` | Fixture paths; facs file route lacks a CLI example; real-host collection stays manual |
| Generate-profile: invalid arguments | 2 | Usage diagnostic on stderr; no collection | U: `test_main_rejects_missing_commands_and_cross_command_options`; `unit/test_facs_profile.py`: `test_facs_cli_rejects_removed_table_path_options` | Process help/validation: #39 |

Handled failures are not a promise that every possible exception is caught.
Successful reports normally use stdout unless a file is selected; diagnostics
must be evaluated separately. Disassemble and profile generation currently route
handled operational errors differently from analyze. Preserve these contracts
unless a separately authorized behavior change says otherwise.

### Host and native prerequisites

Never add ambient `/proc/iomem`, ACPI table access, sudo prompts, or privileged
collection to ordinary tests. Fixture readers/runners protect deterministic
collector behavior; they do not prove real-host access. Real collection needs
separate authorization and records of platform, permissions, and data provenance.
Do not replace failed collection with fabricated empty facts.

Kaitai-generated Python, ast-grep, and the compiled Tree-sitter grammar are
prerequisites, not handwritten test targets. Nix prepares them for the existing
gate. Some tests can skip missing native dependencies: report those skips and
their reasons; they are missing proof, not successful verification.

## Shared development tools

Tools are development-only and versions resolve through `uv.lock`. Outside Nix,
`uv sync --frozen` selects the default dev group; `uv sync --frozen --group mutation`
also selects the mutation tool. These commands do not prepare the native grammar
or Kaitai compiler; use the supported Nix environment for full checks.

Nix currently uses `workspace.deps.all`, so it installs the mutation group too.
The group makes uv selection explicit; it does not isolate installation in Nix.
Ordinary pytest does not start coverage collection or mutation testing.

### Coverage configuration, not a quality score

The configuration measures all handwritten analyzer Python, including adapters,
CLI, errors, and unexecuted modules. Only generated `parsers/generated/` is omitted
within the package; tests, stdlib, and third-party packages are outside its scope.
Do not hide difficult error/debug branches or set a fail-under percentage.

Line-only measurement is the default. Branch runs must use a separate fresh data
file and `--branch`. Python 3.12 uses the `ctrace` core. The subprocess patch
enables parallel data files, which must be combined before reporting; pass the
absolute configuration/data paths to children and allow normal process exit.
Do not mix revisions or line/branch data. A parent-only run does not prove child
instrumentation, and an uninstrumented Nix package must be reported separately.

Python coverage does not measure native components or template execution. Their
observable behavior needs contract/rendering tests, not invented percentages.
Collection automation, child-instrumentation proof, subsystem reports and CI
artifacts belong to [#40](https://github.com/AguTrachta/s3bootscript-analyzer/issues/40).
See [coverage configuration](https://coverage.readthedocs.io/en/latest/config.html).

### Hypothesis profiles

| Profile | Examples | Generation | Intended use |
| --- | --- | --- | --- |
| fast (default) | 100 | Derandomized | Local feedback |
| ci | 100 | Derandomized | Explicit reproducible CI selection |
| exploratory | 1,000 | Non-derandomized | Longer, manual exploration |

All profiles retain health checks, disable the example database and per-example
deadline, and enable failure blobs. This avoids database scratch state and
timing-sensitive failures; bound input size and overall job runtime instead.
Pytest's explicit profile selection overrides the fast default:

```bash
nix develop -c pytest --collect-only --hypothesis-profile=ci
nix develop -c pytest --collect-only --hypothesis-profile=exploratory
```

These commands check collection/profile availability; they do not exercise any
new properties. Property implementations belong to #41 and #42. Their future
tests use the registered `property` marker, public APIs, and independent oracles.
Record Python/Hypothesis versions and replay output. Seeds/blobs are
version-dependent; preserve minimized failures as readable `@example` cases or
fixtures. See [Hypothesis replay guidance](https://hypothesis.readthedocs.io/en/latest/tutorial/replaying-failures.html).

### Mutation pilot configuration only

The pinned mutmut pilot targets only handwritten `analysis/profile.py` and
`analysis/engine.py`, with their existing public contract tests. Copy both `tests/`
and `profiles/`: the profile contract tests discover JSON fixtures recursively,
so omitting profiles would silently skip those cases. The setup uses
`source_paths` and an exact `only_mutate` allowlist, retaining
default stack-depth behavior. No generated or native code is a mutation target.

Run the eventual pilot only in a disposable copy outside the workspace; never
use `mutmut apply` in the working repository. Two workers and a 15-minute overall
budget are the starting limits, not claimed runtime results. A passing selected
baseline is required first. Separate killed, surviving, manually justified
equivalent, invalid, timed-out, and untested/unrun outcomes; timeouts and
infrastructure failures are not assertion kills. Do not chase a mutation score.
Execution and cost/value review belong to [#43](https://github.com/AguTrachta/s3bootscript-analyzer/issues/43).
See [mutmut configuration](https://mutmut.readthedocs.io/en/latest/).

## Record evidence without inventing results

Keep logs, test scratch, and measurement data in an external directory created
with `mktemp -d`. Do not overwrite existing worktree reports. Begin a run record
with this template, replacing placeholders with observed facts:

```yaml
revision: <commit>
dirty_state: <tracked changes and relevant fixture changes>
commands: <exact commands, including environment overrides>
environment: <Python, OS/architecture, uv/Nix and test-tool versions>
dependencies: <uv.lock identity and native-tool/grammar versions>
installation: <development install or explicit packaged executable>
prerequisites_and_skips: <availability, skip reasons, missing proof>
results: <observed outcomes and external artifact locations>
limitations: <failed, unavailable, skipped, or uninstrumented checks>
```

Acceptance evidence adds scenario, exit, streams, file effects, and duration.
Coverage evidence separates statement/branch counts, exclusions, subsystem data,
and instrumentation limits. Property failures retain the minimized input,
invariant and replay instructions. Mutation evidence retains raw tool status,
reviewed classification, rationale and runtime. None is a quality badge.
