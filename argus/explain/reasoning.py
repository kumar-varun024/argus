from typing import List
from argus.explain.models import ReasoningStep
from argus.investigation.models import Investigation
from argus.runtime.mission import Mission
import uuid

class ReasoningChainBuilder:
    """Builds deterministic reasoning chains tracing an investigation back to observations."""
    
    def __init__(self, mission: Mission):
        self.mission = mission

    def build_chain(self, investigation: Investigation) -> List[ReasoningStep]:
        chain = []
        
        # 1. Investigation Creation
        cat_val = investigation.category.value if hasattr(investigation.category, 'value') else str(investigation.category)
        chain.append(ReasoningStep(
            step_id=str(uuid.uuid4()),
            description=f"Investigation created for {cat_val} based on aggregated evidence.",
            source_type="Investigation",
            source_id=str(investigation.id),
            metadata={"category": cat_val, "title": investigation.title}
        ))

        # 2. Evaluation
        chain.append(ReasoningStep(
            step_id=str(uuid.uuid4()),
            description=f"Priority evaluated to {investigation.priority_score:.2f}, Confidence evaluated to {investigation.confidence:.2f}.",
            source_type="Priority",
            source_id=str(investigation.id)
        ))

        # Track seen IDs to avoid duplicating correlations/observations if shared across bundles
        seen_corrs = set()
        seen_obs = set()

        # 3. Evidence Bundles
        for bundle_id in investigation.evidence_bundles:
            bundle = self.mission.evidence_bundles.find(bundle_id)
            if not bundle:
                continue
            
            chain.append(ReasoningStep(
                step_id=str(uuid.uuid4()),
                description=f"Supported by Evidence Bundle '{bundle.description}'.",
                source_type="EvidenceBundle",
                source_id=str(bundle.id),
                metadata={"strength": bundle.strength, "confidence": bundle.confidence}
            ))

            # 4. Correlations
            for corr_id in bundle.correlations:
                if corr_id in seen_corrs:
                    continue
                seen_corrs.add(corr_id)
                corr = self.mission.correlations.find(corr_id)
                if not corr:
                    continue
                chain.append(ReasoningStep(
                    step_id=str(uuid.uuid4()),
                    description=f"Linked by Correlation connecting {len(corr.observations)} observations.",
                    source_type="Correlation",
                    source_id=str(corr.id)
                ))

            # 5. Observations
            for obs_id in bundle.observations:
                if obs_id in seen_obs:
                    continue
                seen_obs.add(obs_id)
                obs = self.mission.observations.find(obs_id)
                if not obs:
                    continue
                chain.append(ReasoningStep(
                    step_id=str(uuid.uuid4()),
                    description=f"Derived from Observation: {obs.title}",
                    source_type="Observation",
                    source_id=str(obs.id),
                    metadata={"source": obs.source, "type": str(getattr(obs, 'category', 'unknown'))}
                ))

        return chain
