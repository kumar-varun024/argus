from typing import Any
from argus.correlation.evidence import EvidenceBundle
from argus.correlation.registry import ObservationRegistry, CorrelationRegistry

class EvidenceStrengthScorer:
    """Calculates Evidence Strength (0-100) for Evidence Bundles."""
    
    def __init__(self, obs_registry: ObservationRegistry, corr_registry: CorrelationRegistry):
        self.obs_registry = obs_registry
        self.corr_registry = corr_registry

    def calculate_strength(self, bundle: EvidenceBundle) -> int:
        """
        Calculate strength based on factors:
        - Independent evidence sources (max 20 points)
        - Evidence diversity (max 20 points)
        - Graph consistency (max 15 points)
        - Workflow consistency (max 15 points)
        - Confidence (Observation/Correlation) (max 30 points)
        Normalize to 0-100.
        """
        if not bundle.observations and not bundle.correlations:
            return 0
            
        # Collect all underlying observations
        obs_list = []
        for oid in bundle.observations:
            o = self.obs_registry.find(oid)
            if o:
                obs_list.append(o)
                
        for cid in bundle.correlations:
            c = self.corr_registry.find(cid)
            if c:
                for oid in c.observations:
                    o = self.obs_registry.find(oid)
                    if o and o not in obs_list:
                        obs_list.append(o)
                        
        if not obs_list:
            return 0

        # 1. Independent sources (0-20)
        sources = set(o.source for o in obs_list)
        score_sources = min(len(sources) * 10, 20)
        
        # 2. Evidence diversity (0-20)
        diversity_count = len(bundle.business_objects) + len(bundle.technologies) + len(bundle.authentication_context)
        score_diversity = min(diversity_count * 5, 20)
        
        # 3. Graph consistency (0-15)
        graph_count = len(bundle.graph_nodes) + len(bundle.graph_edges)
        score_graph = min(graph_count * 3, 15)
        
        # 4. Workflow consistency (0-15)
        score_wf = min(len(bundle.workflows) * 5, 15)
        
        # 5. Average confidence (0-30)
        avg_confidence = sum(o.confidence for o in obs_list) / len(obs_list)
        score_confidence = avg_confidence * 30
        
        total_score = int(score_sources + score_diversity + score_graph + score_wf + score_confidence)
        
        return max(0, min(total_score, 100))
