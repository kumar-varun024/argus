from argus.runtime.mission import Mission
from argus.intelligence.registry import HeuristicRegistry
from argus.intelligence.hypothesis import HypothesisGenerator
from argus.intelligence.confidence import ConfidenceScorer
from argus.intelligence.prioritizer import InvestigationPrioritizer
import logging

logger = logging.getLogger(__name__)

class VulnerabilityIntelligenceEngine:
    """
    Reasoning engine that converts collected knowledge into structured investigation hypotheses.
    """
    
    def __init__(self, registry: HeuristicRegistry = None):
        self.registry = registry or HeuristicRegistry()
        self.generator = HypothesisGenerator(self.registry)
        self.scorer = ConfidenceScorer(self.registry)
        self.prioritizer = InvestigationPrioritizer()
        
    def run(self, mission: Mission):
        """
        Executes the intelligence pipeline over a mission and populates the mission's queue.
        """
        logger.info(f"Starting Vulnerability Intelligence Engine for Mission {mission.id}")
        
        # 1. Generate Hypotheses
        raw_investigations = self.generator.generate(mission)
        logger.info(f"Generated {len(raw_investigations)} raw investigations.")
        
        # 2. Score Confidence
        for inv in raw_investigations:
            inv.confidence = self.scorer.score(inv, mission)
            
        # 3. Prioritize
        sorted_investigations = self.prioritizer.prioritize(raw_investigations)
        
        # 4. Store in Mission
        mission.investigations = sorted_investigations
        
        # The priority queue could be a subset of high confidence, or just the same sorted list
        mission.priority_queue = [inv for inv in sorted_investigations if inv.priority in ["Critical", "High", "Medium"]]
        
        logger.info(f"Stored {len(mission.investigations)} total investigations. {len(mission.priority_queue)} in priority queue.")
