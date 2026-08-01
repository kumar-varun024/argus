from typing import List
from argus.runtime.mission import Mission
from argus.intelligence.models import Investigation
from argus.intelligence.registry import HeuristicRegistry
import logging

logger = logging.getLogger(__name__)

class HypothesisGenerator:
    def __init__(self, registry: HeuristicRegistry):
        self.registry = registry

    def generate(self, mission: Mission) -> List[Investigation]:
        """
        Iterates over all registered heuristics and executes them against the mission context.
        Returns a flat list of raw generated Investigation hypotheses.
        """
        investigations = []
        
        for heuristic in self.registry.get_all():
            try:
                logger.info(f"Running heuristic: {heuristic.name}")
                results = heuristic.run(mission)
                if results:
                    investigations.extend(results)
            except Exception as e:
                logger.error(f"Heuristic {heuristic.id} failed: {e}")
                
        # Deduplicate identical hypotheses
        unique_investigations = {}
        for inv in investigations:
            # Simple deduplication based on title and affected objects
            sig = f"{inv.title}:{'-'.join(sorted(inv.affected_objects))}"
            if sig not in unique_investigations:
                unique_investigations[sig] = inv
                
        return list(unique_investigations.values())
