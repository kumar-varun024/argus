"""AttackSurfaceGraphBuilder: thin class delegating to evidenceBuilder and
missionBuilder. Split from the original monolithic attack_surface.py (see
that module's git history) into argus/graph/attackSurface/ -- behavior
pinned by tests/graph/test_attack_surface_characterization.py.
"""
from __future__ import annotations

from typing import Any, Optional

from argus.evidence.store import EvidenceStore
from argus.graph.graph import KnowledgeGraph
from argus.graph.attackSurface.evidenceBuilder import buildFromEvidence
from argus.graph.attackSurface.missionBuilder import buildFromMission


class AttackSurfaceGraphBuilder:
    """
    Transforms structured reconnaissance evidence from an EvidenceStore
    or Mission into a strongly typed KnowledgeGraph.
    """

    def build_from_evidence(
        self,
        evidence: EvidenceStore,
        target: str = "",
        graph: Optional[KnowledgeGraph] = None,
    ) -> KnowledgeGraph:
        """
        Builds and populates a KnowledgeGraph from structured evidence records.

        Args:
            evidence: EvidenceStore containing discovered evidence.
            target: The root mission target.
            graph: Optional existing KnowledgeGraph to append to.

        Returns:
            KnowledgeGraph: The populated graph.
        """
        return buildFromEvidence(evidence, target=target, graph=graph)

    def build(self, mission: Any) -> KnowledgeGraph:
        """
        Builds and populates a KnowledgeGraph directly from a Mission instance.

        Args:
            mission: The Mission object to build from.

        Returns:
            KnowledgeGraph: The populated graph attached to mission.attack_surface_graph.
        """
        return buildFromMission(self, mission)
