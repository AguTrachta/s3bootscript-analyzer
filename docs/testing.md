# Testing guide

Run the existing checks from the supported Python 3.12 environment:

```bash
nix develop -c scripts/quality-gate
```

This guide establishes the shared foundation for [#38](https://github.com/AguTrachta/s3bootscript-analyzer/issues/38).
Process acceptance is expanded by [#39](https://github.com/AguTrachta/s3bootscript-analyzer/issues/39).
Properties, coverage reports, and the mutation pilot remain separate work.

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
| Development-install subprocess | Real console process with production collaborators in the development environment | Default `tests/acceptance/test_cli_e2e.py` mode |
| Packaged-artifact diagnostic | Explicit built executable without checkout or ambient-tool fallbacks; failures remain visible | The same stories in artifact mode; not a claim of successful package acceptance |

Directory names alone do not establish a boundary. CI currently uses an editable
Nix development environment. Development mode selects the current Python
environment's console executable explicitly; it is still not proof of an isolated
package installation. JUnit suite properties record the resolved executable and
installation mode.

## Current CLI contract matrix

This inventory extends the foundation at `45d2269` with the process stories below.
Test names identify current protection at the stated boundary; artifact-mode
results must be reported separately. Reconcile this table when behavior changes.

Paths in the test column are relative to `tests/`. `I` means
`integration/test_cli_analysis.py`, `R` means `integration/test_report_cli.py`,
`U` means `unit/test_cli.py`, and `A` means `acceptance/test_cli_e2e.py`.

| Command / scenario | Exit | Output contract | Current protection | Remaining gap |
| --- | --- | --- | --- | --- |
| Root/subcommand help | 0 | Help on stdout; no report/collection | A: `test_help_describes_the_public_command`, `test_profile_help_lists_sources_without_collecting` | Real host collection is separate |
| Analyze: findings, stdout | 3 | Markdown or HTML report; stderr empty normally | A: `test_installed_command_prints_profile_filtered_report` | No full renderer matrix duplication |
| Analyze: findings, file | 3 | Report file; stdout/stderr empty normally | A: `test_installed_command_writes_profile_filtered_report_to_file` | Preserve format detail in R |
| Analyze: no match | 0 | Report identifies not_matched, not a safety verdict | A: `test_no_matching_write_returns_zero_with_a_report` | None for this process story |
| Analyze: missing required facts | 0 | Report identifies unknown and missing_profile_data | A: `test_missing_required_profile_facts_remain_unknown` | Richer profile shapes belong to #42 |
| Analyze: disabled rule | 0 | Report identifies skipped | R: `test_disabled_rule_remains_visible_as_skipped` | Retained in-process protection |
| Analyze: invalid selected profile | 1 | Error on stderr; no completed report | A: `test_invalid_selected_profile_fails_without_a_report` | None for this process story |
| Analyze: unreadable input, normal/quiet | 1 | Error on stderr; no completed report | A: `test_unreadable_analysis_input_retains_stderr_errors` | None for this process story |
| Analyze: invalid invocation / debug-quiet conflict | 2 | Usage on stderr; no analysis/report | A: `test_invalid_invocation_fails_without_running_the_command`, `test_debug_and_quiet_conflict_before_creating_a_report` | None for these process cases |
| Analyze: output failure with finding | 1 | Output error on stderr; parent file preserved | A: `test_output_failure_takes_precedence_over_a_finding` | No new atomic-write guarantee |
| Analyze: error then finding | 1 | Report retains finding; errors visible on stderr | A: `test_evaluation_error_preserves_a_later_finding_but_returns_failure` | None for this process story |
| Analyze: debug / quiet success | 3 | Debug on stderr; quiet retains report | A: `test_debug_keeps_diagnostics_separate_from_the_report`, `test_quiet_keeps_the_report_without_informational_output` | Do not redefine quiet as silence |
| Disassemble: text / JSON / semantic | 0 | Selected format on stdout; default text | A: `test_disassemble_prints_text_by_default`, `test_disassemble_prints_structured_json`, `test_disassemble_prints_semantic_operations` | Real-sample breadth remains in `integration/test_real_sample.py` |
| Disassemble: file output | 0 | Requested file; stdout/stderr empty normally | A: `test_disassemble_writes_the_requested_file` | None for this process story |
| Disassemble: handled failure / invalid format | 1 / 2 | Handled errors on stdout; usage on stderr | A: `test_disassemble_handled_failure_stays_on_stdout`, `test_invalid_invocation_fails_without_running_the_command` | Debug behavior retained in U |
| Generate-profile: proc-iomem / kernel success | 0 | JSON on stdout or selected file | U: `test_main_generates_proc_iomem_profile_to_stdout`, `test_main_generates_proc_iomem_profile_to_file`, `test_main_generates_kernel_iomem_profile_to_stdout`, `test_main_generates_kernel_iomem_profile_to_file` | Injected source; not host acceptance |
| Generate-profile: handled proc-iomem / kernel failure | 1 | Handled source/output error on stdout | `unit/test_profile_data.py`: `test_subprocess_runner_rejects_unexpected_return_code` protects runner rejection | CLI failure routing remains an integration gap |
| Generate-profile: facs success / missing tables | 0 / 1 | JSON on stdout or selected file; handled errors on stdout | `unit/test_facs_profile.py`: `test_facs_cli_generates_profile_from_acpi_tables`, `test_facs_cli_reports_missing_table_instead_of_empty_profile` | Fixture paths; facs file-route example absent; host collection stays manual |
| Generate-profile: missing/invalid source | 2 | Usage on stderr; no collection | A: `test_invalid_invocation_fails_without_running_the_command` | No successful host collection claimed |

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

## Run process acceptance

The default development mode uses real parsing, matching, evaluation and
rendering. It preserves the native-tool PATH and editable installation root only
for that mode. Every child has an isolated cwd/HOME/TMPDIR, closed stdin and a
30-second timeout. Other ambient environment variables, including credentials and
Python import overrides, are not forwarded.

```bash
nix develop -c pytest tests/acceptance -q
```

Fixtures are synthetic: a 56-byte table with MEM_WRITE records at offsets 13 and
33, followed by TERMINATE at 53; a profile selects only the first destination.
The curated kernel-write rule is copied into each test directory. The deliberately
broken rule reads an absent generic JSON fact. No fixture is collected from the
host, and no source is decoded with a second implementation to derive expectations.

### Packaged diagnostics

Build and select a non-editable executable explicitly, keeping all evidence and
pytest scratch outside the worktree:

```bash
evidence="$(mktemp -d)"
nix build --no-write-lock-file .#default --no-link --print-out-paths \
  > "$evidence/package-path.txt" 2> "$evidence/build.log"
S3_ACCEPTANCE_MODE=artifact \
S3_ANALYZER_EXECUTABLE="$(cat "$evidence/package-path.txt")/bin/s3bootscript-analyzer" \
  nix develop --no-write-lock-file -c pytest tests/acceptance -q \
    -o "cache_dir=$evidence/cache" --basetemp "$evidence/tmp" \
    --junitxml "$evidence/results.xml"
```

`S3_ACCEPTANCE_MODE` accepts only `development` (default) or `artifact`.
`S3_ANALYZER_EXECUTABLE` optionally overrides the development console path and is
required in artifact mode. Invalid selection fails setup; it never becomes a skip.

Artifact children receive only isolated home/temp settings, a fixed locale,
bytecode suppression and an empty tool directory on PATH. They receive no
REPO_ROOT, PYTHONPATH, PYTHONHOME or development native tools. The test driver may
run under Nix develop; that does not give its environment to the artifact child.
Binary/profile/rule files are explicit CLI inputs, not runtime-resource fallbacks.
JUnit suite properties record the resolved executable/mode, and test cases include
durations, failures and captured diagnostics.

The **Packaged CLI Diagnostics** workflow is manual (`workflow_dispatch`) and has
a 15-minute job budget. It records revision, dirty state, lockfile identity,
platform, driver versions, package path, build log and JUnit/test output, uploading
evidence even after build/test failure with seven-day retention. It is available
after the workflow reaches the default branch and does not replace either
existing PR gate. Failures stay failures: no blanket xfail, skip, or swallowed exit
status. Packaging defects discovered here are separate follow-up work; development
success must not be reported as packaged acceptance.

At the first local isolated probe against the package built from the `45d2269`
production baseline, 20 cases passed and seven analysis cases failed because the
artifact could not locate `ast-grep`. Development mode passed all 27 cases. This
is an observed packaging limitation, not a passing artifact acceptance result or
a reason to weaken those assertions. Packaging/runtime-resource repair is out of
scope here; rerun the diagnostic after that separate work.

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
