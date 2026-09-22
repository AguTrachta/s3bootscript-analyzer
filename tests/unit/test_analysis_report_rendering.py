"""Public analysis-report rendering contract, independent of template layout."""

import re
from dataclasses import replace
from html import unescape

import pytest

from s3bootscript_analyzer.analysis import (
    AnalysisReport,
    Diagnostic,
    EvaluationOutcome,
    MatchEvidence,
    RuleDefinition,
    RuleEvaluation,
    Severity,
)
from s3bootscript_analyzer.cli import build_report_renderer
from s3bootscript_analyzer.errors import BootScriptAnalyzerError


@pytest.fixture(params=["markdown", "html"], name="output_format")
def _output_format(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture(name="rule")
def _rule() -> RuleDefinition:
    return RuleDefinition(
        rule_id="WRITE-CHECK",
        plugin_id="s3bootscript",
        title="Selected destination write",
        description="Check producer-defined sensitive destinations.",
        severity=Severity.WARNING,
        enabled=True,
        required_fields=(),
        matcher_type="ast_grep",
        matcher_config={},
    )


def _report(*evaluations: RuleEvaluation) -> AnalysisReport:
    return AnalysisReport("firmware.bin", "s3bootscript", "producer.json", evaluations)


@pytest.mark.parametrize(
    ("outcome", "severity", "outcome_pattern"),
    [
        (EvaluationOutcome.MATCHED, Severity.CRITICAL, r"\bmatched\b"),
        (EvaluationOutcome.NOT_MATCHED, Severity.CRITICAL, r"\bnot[_ -]matched\b"),
        (EvaluationOutcome.UNKNOWN, Severity.WARNING, r"\bunknown\b"),
        (EvaluationOutcome.ERROR, Severity.INFORMATIONAL, r"\berror\b"),
        (EvaluationOutcome.SKIPPED, Severity.SAFE, r"\bskipped\b"),
    ],
)
def test_rule_outcome_preserves_its_declared_severity(
    rule: RuleDefinition,
    outcome: EvaluationOutcome,
    severity: Severity,
    outcome_pattern: str,
) -> None:
    rule = replace(rule, severity=severity)

    output = build_report_renderer("markdown").render(_report(RuleEvaluation(rule, outcome)))

    assert re.search(outcome_pattern, output, re.IGNORECASE)
    assert re.search(rf"\b{severity.value}\b", output, re.IGNORECASE)


def test_report_identifies_the_analysis_and_lists_rules_in_evaluation_order(
    rule: RuleDefinition, output_format: str
) -> None:
    report = _report(
        RuleEvaluation(rule, EvaluationOutcome.UNKNOWN),
        RuleEvaluation(
            replace(rule, rule_id="A-SECOND", title="Another check", description="Another reason."),
            EvaluationOutcome.NOT_MATCHED,
        ),
    )

    output = build_report_renderer(output_format).render(report)

    assert "firmware.bin" in output
    assert "s3bootscript" in output
    assert "producer.json" in output
    assert output.index("WRITE-CHECK") < output.index("A-SECOND")
    assert "Selected destination write" in output
    assert "Check producer-defined sensitive destinations." in output
    assert "Another check" in output
    assert "Another reason." in output


def test_evidence_includes_captures_and_original_binary_location(
    rule: RuleDefinition, output_format: str
) -> None:
    report = _report(
        RuleEvaluation(
            rule,
            EvaluationOutcome.MATCHED,
            evidence=(
                MatchEvidence({"REGION": "firmware_control"}, "mem[0x1800] <- 0x01", 41, 37, 4660),
            ),
        )
    )

    output = unescape(build_report_renderer(output_format).render(report))

    assert "mem[0x1800] <- 0x01" in output
    assert "REGION" in output
    assert "firmware_control" in output
    assert re.search(r"\brecord\b", output, re.IGNORECASE)
    assert re.search(r"\b37\b", output)
    assert re.search(r"\bline\b", output, re.IGNORECASE)
    assert re.search(r"\b41\b", output)
    assert re.search(r"\boffset\b", output, re.IGNORECASE)
    assert re.search(r"\b(?:0x0*1234|4660)\b", output, re.IGNORECASE)


def test_report_and_rule_diagnostics_preserve_their_explanations_and_sources(
    rule: RuleDefinition, output_format: str
) -> None:
    report = replace(
        _report(
            RuleEvaluation(
                rule,
                EvaluationOutcome.UNKNOWN,
                diagnostics=(
                    Diagnostic(
                        "missing_profile_data", "Required field ranges is absent", "WRITE-CHECK"
                    ),
                ),
            )
        ),
        diagnostics=(Diagnostic("invalid_yaml", "Unterminated sequence", "broken-rule.yaml"),),
    )

    output = build_report_renderer(output_format).render(report)

    assert "missing_profile_data" in output
    assert "Required field ranges is absent" in output
    assert "WRITE-CHECK" in output
    assert "invalid_yaml" in output
    assert "Unterminated sequence" in output
    assert "broken-rule.yaml" in output


def test_html_escapes_producer_and_rule_content(rule: RuleDefinition) -> None:
    report = replace(
        _report(
            RuleEvaluation(
                replace(rule, title='<script>alert("rule")</script>'),
                EvaluationOutcome.MATCHED,
                evidence=(MatchEvidence({"LABEL": "<img src=x>"}, "mem[1] <- 2", 1, 0, 13),),
                diagnostics=(Diagnostic("example", "<iframe>diagnostic</iframe>"),),
            )
        ),
        artifact_name="<svg>firmware</svg>",
    )

    output = build_report_renderer("html").render(report)

    assert re.search(r"<(?:html|body|article|section)\b", output, re.IGNORECASE)
    assert "<script>" not in output
    assert "<img src=x>" not in output
    assert "<iframe>" not in output
    assert "<svg>" not in output
    assert '<script>alert("rule")</script>' in unescape(output)
    assert "<img src=x>" in unescape(output)
    assert "<iframe>diagnostic</iframe>" in unescape(output)
    assert "<svg>firmware</svg>" in unescape(output)
    assert "mem[1] <- 2" in unescape(output)


def test_markdown_evidence_sections_keep_each_location_with_its_match(rule: RuleDefinition) -> None:
    report = _report(
        RuleEvaluation(
            rule,
            EvaluationOutcome.MATCHED,
            evidence=(
                MatchEvidence({"LABEL": "first"}, "mem[0x1800] <- 0x01", 41, 37, 4660),
                MatchEvidence({"LABEL": "second"}, "mem[0x3000] <- 0x02", 53, 49, 22136),
            ),
        )
    )

    sections = build_report_renderer("markdown").render(report).split("#### Evidence ")[1:]

    assert len(sections) == 2
    assert "mem[0x1800] <- 0x01" in sections[0]
    assert "first" in sections[0]
    assert "Record index: 37" in sections[0]
    assert "Semantic line: 41" in sections[0]
    assert "Byte offset: 0x1234" in sections[0]
    assert "mem[0x3000] <- 0x02" in sections[1]
    assert "second" in sections[1]
    assert "Record index: 49" in sections[1]
    assert "Semantic line: 53" in sections[1]
    assert "Byte offset: 0x5678" in sections[1]


def test_markdown_prose_is_literal_and_code_cannot_close_its_fence(rule: RuleDefinition) -> None:
    report = _report(
        RuleEvaluation(
            replace(rule, title="Check *flags* | <script>"),
            EvaluationOutcome.MATCHED,
            evidence=(MatchEvidence({"LABEL": "first"}, "```\n# embedded heading", 1, 0, 13),),
        )
    )

    output = build_report_renderer("markdown").render(report)

    assert "*flags*" not in output
    assert "<script>" not in output
    assert "Check *flags* | <script>" in unescape(output)
    assert "````\n```\n# embedded heading\n````" in output


def test_markdown_capture_value_is_literal_code(rule: RuleDefinition) -> None:
    report = _report(
        RuleEvaluation(
            rule,
            EvaluationOutcome.MATCHED,
            evidence=(
                MatchEvidence(
                    {"LABEL": "*flags*\n\n# embedded heading"},
                    "mem[0x1800] <- 0x01",
                    1,
                    0,
                    13,
                ),
            ),
        )
    )

    output = build_report_renderer("markdown").render(report)

    assert "LABEL:" in output
    assert "```\n*flags*\n\n# embedded heading\n```" in output
    assert "<code>" not in output


def test_unsupported_report_format_is_an_expected_application_error() -> None:
    with pytest.raises(BootScriptAnalyzerError, match="Unsupported report format"):
        build_report_renderer("xml")
