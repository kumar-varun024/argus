from argus.correlation.evidence import EvidenceBundle

class ConfidenceCalculator:
    """Calculates overall Evidence Bundle confidence."""
    
    def calculate_confidence(self, bundle: EvidenceBundle) -> float:
        """
        Calculate confidence (0.0 - 1.0) using:
        - Evidence strength
        - Observation/Correlation quality (simplified as length of underlying items)
        - Graph/Workflow quality
        Never use AI confidence alone.
        """
        # Base confidence from strength (0-100) -> (0.0-1.0)
        base_conf = bundle.strength / 100.0
        
        # Adjust based on observation/correlation counts
        quality_bonus = min((len(bundle.observations) + len(bundle.correlations)) * 0.05, 0.2)
        
        # Adjust based on graph/workflow quality
        graph_bonus = min(len(bundle.graph_nodes) * 0.02, 0.1)
        wf_bonus = min(len(bundle.workflows) * 0.02, 0.1)
        
        total_conf = base_conf + quality_bonus + graph_bonus + wf_bonus
        
        return max(0.0, min(total_conf, 1.0))
