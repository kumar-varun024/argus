import logging
from typing import List, Any, Optional
from argus.investigation.models import Investigation, InvestigationPriority
from argus.investigation.scoring import ScoreCalculator
from argus.investigation.weights import WeightConfig
from argus.investigation.ranking import InvestigationRanker

from argus.graph.graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class PriorityEngine:
    """
    Evaluates investigations and updates their priority, score, and explanation
    without determining whether something is a vulnerability.
    """
    
    def __init__(self, bundle_registry: Any = None, weight_config: Optional[WeightConfig] = None):
        self.bundle_registry = bundle_registry
        self.weight_config = weight_config or WeightConfig()
        self.score_calculator = ScoreCalculator(self.weight_config)
        
    def evaluate(self, investigation: Investigation, mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> InvestigationPriority:
        """
        Calculates priority score, updates the investigation model,
        and returns the assigned priority level.
        """
        self.weight_config.log_weights()
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        
        score, explanations = self.score_calculator.calculate(
            investigation, 
            self.bundle_registry, 
            mission,
            graph=kg
        )
        
        investigation.priority_score = score
        investigation.priority_explanation = explanations
        investigation.priority = self._map_score_to_priority(score)
        
        logger.info(
            f"Priority calculated for {investigation.id}: {investigation.priority.value} "
            f"({score:.1f}) - {', '.join(explanations)}"
        )
        
        return investigation.priority

    def evaluate_all(self, investigations: List[Investigation], mission: Any = None, graph: Optional[KnowledgeGraph] = None) -> List[Investigation]:
        """
        Evaluates a list of investigations, updates scores, priority, and explanations,
        ranks them highest first, updates mission storage if provided, and returns the ranked list.
        """
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        for inv in investigations:
            self.evaluate(inv, mission, graph=kg)
            
        ranked = InvestigationRanker.rank(investigations, highest_first=True)
        
        if mission is not None:
            mission.priority_scores = {str(inv.id): inv.priority_score for inv in investigations}
            mission.priority_queue = [str(inv.id) for inv in ranked]
            logger.info(f"Queue reordered: {len(mission.priority_queue)} items in mission.priority_queue")
            
        return ranked

    def _map_score_to_priority(self, score: float) -> InvestigationPriority:
        if score >= 90.0:
            return InvestigationPriority.CRITICAL
        elif score >= 70.0:
            return InvestigationPriority.HIGH
        elif score >= 40.0:
            return InvestigationPriority.MEDIUM
        elif score >= 10.0:
            return InvestigationPriority.LOW
        else:
            return InvestigationPriority.INFORMATIONAL
