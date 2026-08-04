from argus.correlation.correlation import Correlation
from argus.correlation.registry import ObservationRegistry

class CorrelationScorer:
    """Calculates a normalized correlation score (0-100)."""

    def __init__(self, observation_registry: ObservationRegistry):
        self.registry = observation_registry

    def calculate_score(self, correlation: Correlation) -> int:
        """
        Calculate score based on factors:
        - Average Observation confidence (max 40 points)
        - Unique Business Objects overlap (max 15 points)
        - Unique Workflows overlap (max 15 points)
        - Unique Auth Contexts (max 15 points)
        - Technology / Tag overlap (max 15 points)
        Normalize to 0-100.
        """
        if not correlation.observations:
            return 0
            
        observations = [self.registry.find(oid) for oid in correlation.observations]
        observations = [o for o in observations if o is not None]
        
        if not observations:
            return 0
            
        # 1. Observation Confidence (0-40)
        avg_confidence = sum(o.confidence for o in observations) / len(observations)
        score_confidence = avg_confidence * 40
        
        # 2. Business Object Weight (0-15)
        # More shared business objects implies higher correlation value
        score_bo = min(len(correlation.business_objects) * 5, 15)
        
        # 3. Workflows Weight (0-15)
        score_wf = min(len(correlation.workflows) * 5, 15)
        
        # 4. Auth Contexts Weight (0-15)
        auth_len = len(correlation.authentication_context) + len(correlation.authorization_context)
        score_auth = min(auth_len * 5, 15)
        
        # 5. Technology / Graph nodes Weight (0-15)
        tech_len = len(correlation.technologies) + len(correlation.graph_nodes)
        score_tech = min(tech_len * 3, 15)
        
        # 6. Evidence overlap Weight (0-15)
        evidence_set = set()
        for o in observations:
            for ev in o.evidence:
                try:
                    evidence_set.add(str(ev))
                except Exception:
                    pass
        score_evidence = min(len(evidence_set) * 3, 15)
        
        total_score = int(score_confidence + score_bo + score_wf + score_auth + score_tech + score_evidence)
        
        # Normalize strictly between 0 and 100
        return max(0, min(total_score, 100))
