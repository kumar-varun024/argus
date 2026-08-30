import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from argus.runtime.mission import Mission

from argus.hypothesis.models import Hypothesis
from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class HypothesisConfidenceScorer:
    """Calculates a confidence score for a hypothesis based on its supporting evidence and graph topology."""

    def calculate_confidence(self, hypothesis: Hypothesis, mission_context: 'Mission' = None, graph: Optional[KnowledgeGraph] = None) -> float:
        """
        Calculate confidence based on related investigations, evidence, and attack surface graph topology.
        """
        base_confidence = 0.0
        
        # If we have mission context, we can inspect the actual evidence
        if mission_context:
            base_confidence = self._calculate_from_mission(hypothesis, mission_context)
        else:
            # Fallback to taking max of related investigation confidences (if any exist in metadata)
            base_confidence = hypothesis.metadata.get('max_investigation_confidence', 0.2)

        # Penalize if too few pieces of evidence
        num_evidence = len(hypothesis.related_evidence) + len(hypothesis.related_observations)
        if num_evidence == 1:
            base_confidence *= 0.8
        elif num_evidence == 0:
            base_confidence = 0.0

        # Graph Topology Modulation
        kg = graph or (getattr(mission_context, 'attack_surface_graph', None) if mission_context else None)
        if kg is not None and hasattr(kg, 'nodes') and kg.node_count() > 0:
            candidate_node_ids = set(hypothesis.supporting_graph_nodes or [])
            for ep in (hypothesis.related_endpoints or []):
                candidate_node_ids.add(str(ep))
                candidate_node_ids.add(f"endpoint:{ep}")
                candidate_node_ids.add(f"live_host:{ep}")

            resolved_nodes = []
            for cid in candidate_node_ids:
                if cid in kg.nodes:
                    resolved_nodes.append(kg.nodes[cid])
                else:
                    for nid, n in kg.nodes.items():
                        if n.value == cid or (n.metadata and (n.metadata.get("url") == cid or n.metadata.get("host") == cid)):
                            resolved_nodes.append(n)

            # Find host nodes
            host_nodes = {}
            for n in resolved_nodes:
                if n.type == "live_host":
                    host_nodes[n.id] = n
                elif hasattr(kg, 'get_host_for_node'):
                    h = kg.get_host_for_node(n)
                    if h:
                        host_nodes[h.id] = h

            max_degree = 0
            for h in host_nodes.values():
                if hasattr(kg, 'get_node_degree'):
                    deg = kg.get_node_degree(h)
                    if deg > max_degree:
                        max_degree = deg
            for n in resolved_nodes:
                if hasattr(kg, 'get_node_degree'):
                    deg = kg.get_node_degree(n)
                    if deg > max_degree:
                        max_degree = deg

            # Connectivity multiplier: 0.85 + min(0.35, max_degree * 0.07)
            connectivity_multiplier = 0.85 + min(0.35, max_degree * 0.07)
            base_confidence *= connectivity_multiplier

            # Vulnerability bonus: 1.10 if host has HAS_VULNERABILITY edge
            has_vulnerability = False
            host_ids = set(host_nodes.keys())
            resolved_ids = {n.id for n in resolved_nodes}
            target_ids = host_ids | resolved_ids

            for e in kg.edges:
                if e.type == "HAS_VULNERABILITY" and (e.source in target_ids or e.target in target_ids):
                    has_vulnerability = True
                    break

            if not has_vulnerability:
                for n in resolved_nodes:
                    if n.type == "vulnerability":
                        has_vulnerability = True
                        break

            if has_vulnerability:
                base_confidence *= 1.10

        # Bound the score
        final_confidence = min(max(base_confidence, 0.0), 1.0)
        return float(round(final_confidence, 4))

    def _calculate_from_mission(self, hypothesis: Hypothesis, mission: 'Mission') -> float:
        """Calculate confidence by resolving related UUIDs against mission registries."""
        evidence_confidences = []
        
        # Check evidence bundles
        for evid in hypothesis.related_evidence:
            if hasattr(mission, 'evidence_bundles'):
                bundle = mission.evidence_bundles.find(evid)
                if bundle:
                    evidence_confidences.append(bundle.confidence)
                    
        # Check investigations
        for iid in hypothesis.related_investigations:
            if hasattr(mission, 'investigations'):
                inv = mission.investigations.find(iid)
                if inv:
                    evidence_confidences.append(inv.confidence)

        if not evidence_confidences:
            return 0.1

        # Use the highest confidence as base, and add a small bonus for corroborating evidence
        max_conf = max(evidence_confidences)
        bonus = (len(evidence_confidences) - 1) * 0.05
        return min(max_conf + bonus, 1.0)
