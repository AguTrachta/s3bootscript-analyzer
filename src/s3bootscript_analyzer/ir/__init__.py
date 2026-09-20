"""Intermediate representations exposed by analyzer plugins."""

from s3bootscript_analyzer.ir.semantic import (
    SemanticIrBuilder,
    SemanticIrDocument,
    SemanticSourceReference,
)

__all__ = [
    "SemanticIrBuilder",
    "SemanticIrDocument",
    "SemanticSourceReference",
]
