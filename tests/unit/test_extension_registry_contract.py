"""Executable contract for resolving trusted plugin facades by identifier."""

from collections.abc import Iterable

import pytest

from s3bootscript_analyzer.analysis import Diagnostic, MatchEvidence, RuleDefinition
from s3bootscript_analyzer.extensions import (
    AnalysisDocument,
    DuplicateExtensionError,
    PluginCatalog,
    UnknownExtensionError,
)
from s3bootscript_analyzer.ingest import BinarySource


class FakeDocument:
    plugin_id = "s3bootscript"
    diagnostics: tuple[Diagnostic, ...] = ()


class FakePlugin:
    plugin_id = "s3bootscript"

    def decode(self, _source: BinarySource) -> FakeDocument:
        return FakeDocument()

    def match(
        self,
        _document: AnalysisDocument,
        _rule: RuleDefinition,
    ) -> Iterable[MatchEvidence]:
        return ()


def test_plugin_catalog_resolves_a_registered_instance() -> None:
    plugin = FakePlugin()

    catalog = PluginCatalog(plugins=[plugin])

    assert catalog.resolve("s3bootscript") is plugin


@pytest.mark.parametrize("plugin_id", ["unknown", "os.system", "../../plugin.py"])
def test_plugin_catalog_never_imports_rule_supplied_identifiers(plugin_id: str) -> None:
    catalog = PluginCatalog(plugins=[FakePlugin()])

    with pytest.raises(UnknownExtensionError):
        catalog.resolve(plugin_id)


def test_plugin_catalog_rejects_duplicate_identifiers() -> None:
    with pytest.raises(DuplicateExtensionError):
        PluginCatalog(plugins=[FakePlugin(), FakePlugin()])
