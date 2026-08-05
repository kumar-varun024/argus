from argus.investigation.models import Investigation
from argus.correlation.registry import EvidenceBundleRegistry, CorrelationRegistry, ObservationRegistry
from typing import Dict, Any

class ReasoningTreeBuilder:
    """Builds reasoning chains explaining the provenance of Investigations."""
    
    def __init__(self, bundle_registry: EvidenceBundleRegistry, corr_registry: CorrelationRegistry, obs_registry: ObservationRegistry):
        self.bundle_registry = bundle_registry
        self.corr_registry = corr_registry
        self.obs_registry = obs_registry
        
    def build_tree(self, investigation: Investigation) -> Dict[str, Any]:
        """
        Constructs the Reasoning Tree: Observation -> Correlation -> EvidenceBundle -> Investigation.
        """
        tree = {
            "investigation": str(investigation.id),
            "evidence_bundles": []
        }
        
        for bid in investigation.evidence_bundles:
            bundle = self.bundle_registry.find(bid)
            if not bundle:
                continue
                
            bundle_node = {
                "bundle_id": str(bundle.id),
                "correlations": [],
                "observations": []
            }
            
            # Map observations directly in the bundle
            for oid in bundle.observations:
                obs = self.obs_registry.find(oid)
                if obs:
                    bundle_node["observations"].append(str(obs.id))
                    
            # Map correlations and their underlying observations
            for cid in bundle.correlations:
                corr = self.corr_registry.find(cid)
                if corr:
                    corr_node = {
                        "correlation_id": str(corr.id),
                        "observations": [str(o) for o in corr.observations]
                    }
                    bundle_node["correlations"].append(corr_node)
                    
            tree["evidence_bundles"].append(bundle_node)
            
        return tree
        
    def generate_reasoning_text(self, investigation: Investigation) -> str:
        """Generates the human-readable reasoning summary."""
        text = "This investigation is backed by multiple evidence sources.\n"
        
        if investigation.workflows and investigation.business_objects:
            text += f"Administrative workflow detected involving {', '.join(investigation.business_objects)} objects.\n"
            
        text += "Multiple evidence bundles indicate relationships across the application."
        return text
