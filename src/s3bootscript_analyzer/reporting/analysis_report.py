"""Jinja templates render analysis results without interpreting rule policy."""

from __future__ import annotations

import re
from html import escape

from jinja2 import Environment, PackageLoader, StrictUndefined, TemplateError, select_autoescape

from s3bootscript_analyzer.analysis import AnalysisReport, ReportRenderer
from s3bootscript_analyzer.errors import BootScriptAnalyzerError

_TEMPLATES = {"markdown": "report.md.j2", "html": "report.html.j2"}


class JinjaReportRenderer(ReportRenderer):
    """Render a report with the package-owned template for one output format."""

    def __init__(self, output_format: str) -> None:
        if output_format not in _TEMPLATES:
            raise BootScriptAnalyzerError(f"Unsupported report format: {output_format}")
        self._template_name = _TEMPLATES[output_format]
        self._environment = Environment(
            loader=PackageLoader("s3bootscript_analyzer.reporting"),
            undefined=StrictUndefined,
            autoescape=select_autoescape(("html", "html.j2"), default_for_string=True),
            keep_trailing_newline=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._environment.filters["markdown_text"] = _markdown_text
        self._environment.filters["code_block"] = _code_block

    def render(self, report: AnalysisReport) -> str:
        try:
            return self._environment.get_template(self._template_name).render(report=report)
        except (TemplateError, OSError, UnicodeError) as ex:
            raise BootScriptAnalyzerError(f"Unable to render analysis report: {ex}") from ex


def _markdown_text(value: object) -> str:
    text = escape(" ".join(str(value).splitlines()), quote=False)
    return re.sub(r"[\\`*_\[\]|#]", _markdown_entity, text)


def _markdown_entity(match: re.Match[str]) -> str:
    return f"&#{ord(match.group())};"


def _code_block(value: object) -> str:
    text = str(value)
    fence = "`" * max(3, 1 + max(map(len, re.findall(r"`+", text)), default=0))
    return f"{fence}\n{text}\n{fence}"
