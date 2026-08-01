from typing import Dict, Any
from argus.intelligence.models import Investigation

class APIConfidenceScorer:
    def score(self, inv: Investigation, context: Dict[str, Any]) -> float:
        score = 60.0
        
        resources = context.get('resources', {})
        operations = context.get('operations', [])
        
        if len(resources) > 5:
            score *= 1.2
            
        if len(operations) > 10:
            score *= 1.1
            
        return min(max(score, 0.0), 100.0)
