"""Trusted analysis plugins resolved only from an application-owned catalog."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import TYPE_CHECKING

from s3bootscript_analyzer.ingest.source import BinarySource

if TYPE_CHECKING:
    from s3bootscript_analyzer.analysis.models import (
        Diagnostic,
        MatchEvidence,
        RuleDefinition,
    )


class UnknownExtensionError(LookupError):
    """Raised when trusted code did not register an identifier."""


class DuplicateExtensionError(ValueError):
    """Raised when trusted composition contains an ambiguous identifier."""


class AnalysisDocument(ABC):
    """Minimum document behavior shared across analysis plugins."""

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Return the identifier of the plugin that produced the document."""

    @property
    @abstractmethod
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        """Return recoverable diagnostics produced while decoding."""


class AnalysisPlugin(ABC):
    """Trusted facade for decoding and matching one artifact family."""

    @property
    @abstractmethod
    def plugin_id(self) -> str:
        """Return the trusted plugin identifier."""

    @abstractmethod
    def decode(self, source: BinarySource) -> AnalysisDocument:
        """Decode an artifact into the plugin-owned analysis document."""

    @abstractmethod
    def match(
        self,
        document: AnalysisDocument,
        rule: RuleDefinition,
    ) -> Iterable[MatchEvidence]:
        """Return matches in stable source order."""


class PluginCatalog:
    """Resolve trusted plugin facades without dynamic rule imports."""

    def __init__(self, plugins: Iterable[AnalysisPlugin] = ()) -> None:
        self._plugins: dict[str, AnalysisPlugin] = {}
        for plugin in plugins:
            self._register(plugin)

    def resolve(self, plugin_id: str) -> AnalysisPlugin:
        """Return a registered plugin or fail without importing anything."""
        try:
            return self._plugins[plugin_id]
        except KeyError as ex:
            raise UnknownExtensionError(f"Unknown analyzer plugin: {plugin_id}") from ex

    def _register(self, plugin: AnalysisPlugin) -> None:
        if plugin.plugin_id in self._plugins:
            raise DuplicateExtensionError(f"Duplicate analyzer plugin: {plugin.plugin_id}")
        self._plugins[plugin.plugin_id] = plugin
