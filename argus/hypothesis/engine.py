import logging
from typing import Optional, List, TYPE_CHECKING
from argus.investigation.models import Investigation
from argus.hypothesis.models import Hypothesis, HypothesisStatus
from argus.hypothesis.registry import HypothesisRegistry
from argus.hypothesis.confidence import HypothesisConfidenceScorer
from argus.hypothesis.ranking import HypothesisRanker
from argus.hypothesis.lifecycle import HypothesisLifecycleManager
from argus.hypothesis.generator import HypothesisGenerator

from argus.graph.graph import KnowledgeGraph

if TYPE_CHECKING:
    from argus.runtime.mission import Mission

logger = logging.getLogger(__name__)

class HypothesisEngine:
    """Facade for the Hypothesis Engine, orchestrating hypothesis generation and lifecycle."""
    
    def __init__(self, registry: Optional[HypothesisRegistry] = None):
        self.registry = registry or HypothesisRegistry()
        self.conf_scorer = HypothesisConfidenceScorer()
        self.ranker = HypothesisRanker()
        self.lifecycle = HypothesisLifecycleManager()
        self.generator = HypothesisGenerator(self.registry, self.conf_scorer, self.ranker)

    def process_investigation(self, investigation: Investigation, mission: 'Mission' = None, graph: Optional[KnowledgeGraph] = None) -> Optional[Hypothesis]:
        """
        Main entry point for generating or refining a hypothesis from an investigation.
        """
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        hyp = self.generator.process_investigation(investigation, mission, graph=kg)
        if hyp:
            logger.info(f"HypothesisEngine processed investigation {investigation.id} into hypothesis {hyp.id}")
            
            # Optionally transition to PROPOSED if confidence is very high
            if hyp.status == HypothesisStatus.DRAFT and hyp.confidence > 0.8:
                self.lifecycle.propose(hyp, mission)
                
        return hyp

    def evaluate_all(self, mission: 'Mission' = None, graph: Optional[KnowledgeGraph] = None) -> None:
        """
        Re-evaluates confidence and priority for all hypotheses.
        """
        kg = graph or (getattr(mission, 'attack_surface_graph', None) if mission else None)
        for hyp in self.registry.get_all():
            hyp.confidence = self.conf_scorer.calculate_confidence(hyp, mission, graph=kg)
            self.ranker.evaluate_priority(hyp, mission, graph=kg)
            
    def get_ranked_hypotheses(self) -> List[Hypothesis]:
        """Returns all hypotheses, sorted by highest priority and confidence."""
        return self.ranker.rank(self.registry.get_all())
