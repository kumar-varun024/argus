from typing import Dict, Any
from argus.intelligence.models import Investigation

class AuthenticationConfidenceScorer:
    def score(self, inv: Investigation, context: Dict[str, Any]) -> float:
        score = 65.0
        
        # If there's multiple pieces of evidence, increase confidence
        if len(inv.supporting_evidence) > 1:
            score *= 1.15
            
        return min(max(score, 0.0), 100.0)
