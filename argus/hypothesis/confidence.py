import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from argus.runtime.mission import Mission

from argus.hypothesis.models import Hypothesis

logger = logging.getLogger(__name__)

class HypothesisConfidenceScorer:
    """Calculates a confidence score for a hypothesis based on its supporting evidence."""

    def calculate_confidence(self, hypothesis: Hypothesis, mission_context: 'Mission' = None) -> float:
        """
        Calculate confidence based on related investigations and evidence.
        """
        base_confidence = 0.0
        
        # If we have mission context, we can inspect the actual evidence
        if mission_context:
            base_confidence = self._calculate_from_mission(hypothesis, mission_context)
        else:
            # Fallback to taking max of related investigation confidences (if any exist in metadata)
            # This is less accurate but works if full context isn't passed
            base_confidence = hypothesis.metadata.get('max_investigation_confidence', 0.2)

        # Penalize if too few pieces of evidence
        num_evidence = len(hypothesis.related_evidence) + len(hypothesis.related_observations)
        if num_evidence == 1:
            base_confidence *= 0.8
        elif num_evidence == 0:
            base_confidence = 0.0

        # Bound the score
        final_confidence = min(max(base_confidence, 0.0), 1.0)
        return final_confidence

    def _calculate_from_mission(self, hypothesis: Hypothesis, mission: 'Mission') -> float:
        """Calculate confidence by resolving related UUIDs against mission registries."""
        evidence_confidences = []
        
        # Check evidence bundles
        for evid in hypothesis.related_evidence:
            if hasattr(mission, 'evidence_bundles'):
                bundle = mission.evidence_bundles.find(evid)
                if bundle:
                    evidence_confidences.append(bundle.confidence)
                    
        # Check investigations
        for iid in hypothesis.related_investigations:
            if hasattr(mission, 'investigations'):
                inv = mission.investigations.find(iid)
                if inv:
                    evidence_confidences.append(inv.confidence)

        if not evidence_confidences:
            return 0.1

        # Use the highest confidence as base, and add a small bonus for corroborating evidence
        max_conf = max(evidence_confidences)
        bonus = (len(evidence_confidences) - 1) * 0.05
        return min(max_conf + bonus, 1.0)
