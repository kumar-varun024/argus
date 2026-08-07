import logging
from argus.benchmark.ground_truth.models import ComparisonResult, GroundTruth
from argus.benchmark.ground_truth.comparison import GroundTruthComparer
from argus.benchmark.ground_truth.registry import GroundTruthRegistry
from argus.runtime.mission import Mission

logger = logging.getLogger(__name__)

class GroundTruthEngine:
    """Facade for the Ground Truth evaluation subsystem."""
    
    def __init__(self):
        self.registry = GroundTruthRegistry()
        
    def evaluate(self, mission: Mission) -> ComparisonResult:
        """Evaluates a completed mission against its associated ground truth."""
        logger.info(f"Comparison started for mission {mission.id}")
        
        dataset_id = getattr(mission, "dataset_id", None)
        gt = None
        if dataset_id:
            gt = self.registry.get_by_dataset(dataset_id)
        
        if not gt and len(self.registry.list_all()) > 0:
            gt = self.registry.list_all()[0] # Fallback for local run
            
        if not gt:
            raise ValueError(f"No ground truth found for mission {mission.id}")
            
        logger.info(f"Ground Truth loaded. Comparing against {gt.id}")
        
        result = GroundTruthComparer.compare(gt, mission)
        
        for match in result.matches:
            if match.status.value == "Matched":
                logger.info(f"Expectation matched: {match.category} - {match.expected}")
                
        for miss in result.misses:
            logger.info(f"Expectation missed: {miss.category} - {miss.expected}")
            
        for un in result.unexpected_findings:
            logger.info(f"Unexpected finding recorded: {un.category} - {un.actual}")
        
        logger.info(f"Comparison completed. Matches: {result.total_matched}, Partials: {result.total_partially_matched}, Misses: {len(result.misses)}, Unexpected: {len(result.unexpected_findings)}")
        
        return result
