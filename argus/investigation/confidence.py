from argus.investigation.models import Investigation
from argus.correlation.registry import EvidenceBundleRegistry

class InvestigationConfidenceScorer:
    """Calculates overall Investigation confidence based on underlying Evidence Bundles."""
    
    def __init__(self, bundle_registry: EvidenceBundleRegistry):
        self.bundle_registry = bundle_registry
        
    def calculate_confidence(self, investigation: Investigation) -> float:
        """
        Calculate confidence (0.0 - 1.0) using:
        - Maximum confidence of the underlying evidence bundles.
        - Boosted slightly by the number of supporting bundles.
        """
        if not investigation.evidence_bundles:
            return 0.0
            
        max_bundle_conf = 0.0
        valid_bundles = 0
        
        for bid in investigation.evidence_bundles:
            bundle = self.bundle_registry.find(bid)
            if bundle:
                valid_bundles += 1
                if bundle.confidence > max_bundle_conf:
                    max_bundle_conf = bundle.confidence
                    
        # Small boost for multiple bundles, up to +0.15
        boost = min((valid_bundles - 1) * 0.05, 0.15) if valid_bundles > 1 else 0.0
        
        total_conf = max_bundle_conf + boost
        return max(0.0, min(total_conf, 1.0))
