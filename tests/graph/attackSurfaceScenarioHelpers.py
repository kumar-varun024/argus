"""Shared helpers for the AttackSurfaceGraphBuilder characterization scenarios
(tests/graph/test_attack_surface_characterization.py).
"""
from __future__ import annotations

from typing import Any, Dict

from argus.evidence.model import Evidence
from argus.graph.graph import KnowledgeGraph


def ev(category: str, value: str = "", metadata: Dict[str, Any] = None, title: str = "", severity: str = "info", source: str = "") -> Evidence:
    return Evidence(category=category, value=value, metadata=metadata or {}, title=title, severity=severity, source=source)


def graphSnapshot(graph: KnowledgeGraph) -> dict:
    nodes = {nid: {"type": n.type, "value": n.value, "metadata": n.metadata} for nid, n in graph.nodes.items()}
    edges = [{"source": e.source, "target": e.target, "type": e.type, "metadata": e.metadata} for e in graph.edges]
    return {"nodes": nodes, "edges": edges}


class DictLikeMission:
    """Minimal stand-in for Mission exposing only the attributes build() reads."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
