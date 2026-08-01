from argus.intelligence.models import Investigation
from argus.runtime.mission import Mission
from argus.intelligence.registry import HeuristicRegistry

class ConfidenceScorer:
    def __init__(self, registry: HeuristicRegistry):
        self.registry = registry

    def score(self, investigation: Investigation, mission: Mission) -> float:
        """
        Calculates a 0-100 confidence score for the investigation based on:
        - The base score from the heuristic that generated it
        - Evidence quality (amount of supporting evidence)
        - Workflow completeness
        """
        base_score = 0.5  # default
        
        # In a real implementation, we would trace the investigation back to the specific 
        # heuristic that generated it and call heuristic.score(investigation).
        # For now, we simulate this by looking for hints in the category.
        
        # Evaluate Evidence
        evidence_multiplier = 1.0
        if len(investigation.supporting_evidence) == 0:
            evidence_multiplier = 0.5
        elif len(investigation.supporting_evidence) > 2:
            evidence_multiplier = 1.2
            
        # Evaluate Workflow completeness
        workflow_multiplier = 1.0
        if investigation.workflow:
            workflow_multiplier = 1.1
            
        # Calculate raw score
        raw_score = (base_score * evidence_multiplier * workflow_multiplier) * 100
        
        # Clamp between 0 and 100
        return max(0.0, min(100.0, raw_score))
