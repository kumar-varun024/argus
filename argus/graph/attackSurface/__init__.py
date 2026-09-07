"""Attack surface graph construction, split into a sub-package.

All public names re-exported for import-path compatibility with the
former argus.graph.attack_surface module.
"""
from argus.graph.attackSurface.builder import AttackSurfaceGraphBuilder

__all__ = ["AttackSurfaceGraphBuilder"]
