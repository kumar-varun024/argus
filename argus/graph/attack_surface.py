"""Transforms structured reconnaissance evidence into a strongly typed
KnowledgeGraph.

Split into argus.graph.attackSurface (sub-package); re-exported here for
import-path compatibility.
"""
from argus.graph.attackSurface import AttackSurfaceGraphBuilder

__all__ = ["AttackSurfaceGraphBuilder"]
