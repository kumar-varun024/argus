import logging
from typing import List, Dict, Any, Optional
from argus.hypothesis.models import Hypothesis, HypothesisPriority
from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class HypothesisRanker:
    """Evaluates and ranks hypotheses based on evidence, impact, confidence, and graph topology."""

    @staticmethod
    def rank(hypotheses: List[Hypothesis], highest_first: bool = True,
             category: str = None, priority: str = None,
             business_object: str = None, workflow: str = None, status: str = None) -> List[Hypothesis]:
        """Rank a list of hypotheses and optionally filter them."""
        
        filtered = []
        for hyp in hypotheses:
            if category and hyp.category.value != category:
                continue
            if priority and hyp.priority.value != priority:
                continue
            if business_object and business_object not in hyp.business_objects:
                continue
            if workflow and workflow not in hyp.workflows:
                continue
            if status and hyp.status.value != status:
                continue
            filtered.append(hyp)

        # Sort by priority_score, then confidence
        filtered.sort(key=lambda h: (h.priority_score, h.confidence), reverse=highest_first)
        return filtered

    def evaluate_priority(self, hypothesis: Hypothesis, mission_context: Any = None, graph: Optional[KnowledgeGraph] = None) -> float:
        """
        Calculate a priority score (0-100) for a hypothesis.
        """
        score = 0.0
        
        # 1. Base score from Confidence (up to 40 points)
        score += hypothesis.confidence * 40.0
        
        # 2. Business Impact (up to 20 points)
        if hypothesis.business_objects:
            score += min(len(hypothesis.business_objects) * 5, 20)
            
        # 3. Workflow Importance (up to 20 points)
        if hypothesis.workflows:
            score += min(len(hypothesis.workflows) * 10, 20)
            
        # 4. Evidence Strength / Volume (up to 20 points)
        total_evidence = len(hypothesis.related_evidence) + len(hypothesis.related_investigations)
        score += min(total_evidence * 5, 20)

        # 5. Topology Connectivity (up to 10 bonus points)
        kg = graph or (getattr(mission_context, 'attack_surface_graph', None) if mission_context else None)
        if kg is not None and hasattr(kg, 'nodes'):
            nodes_count = len(hypothesis.supporting_graph_nodes) + len(hypothesis.supporting_graph_edges)
            if nodes_count > 0:
                score += min(nodes_count * 2.5, 10.0)

        # Update the hypothesis fields
        hypothesis.priority_score = min(score, 100.0)
        
        # Assign categorical priority based on score
        if score >= 80:
            hypothesis.priority = HypothesisPriority.CRITICAL
        elif score >= 60:
            hypothesis.priority = HypothesisPriority.HIGH
        elif score >= 40:
            hypothesis.priority = HypothesisPriority.MEDIUM
        else:
            hypothesis.priority = HypothesisPriority.LOW
            
        return hypothesis.priority_score
