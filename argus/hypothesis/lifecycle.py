import logging
from typing import Any
from argus.hypothesis.models import Hypothesis, HypothesisStatus, HypothesisHistoryEntry

logger = logging.getLogger(__name__)

class HypothesisLifecycleManager:
    """Manages the state transitions of Hypotheses and records history."""

    def transition(self, hypothesis: Hypothesis, new_status: HypothesisStatus, reason: str, mission: Any = None) -> bool:
        """
        Transition a hypothesis to a new status, recording the history.
        """
        if hypothesis.status == new_status:
            return False

        old_status = hypothesis.status
        hypothesis.status = new_status
        
        entry = HypothesisHistoryEntry(
            status=new_status,
            reason=reason,
            confidence=hypothesis.confidence
        )
        hypothesis.history.append(entry)
        
        # Also log to mission history if available
        if mission and hasattr(mission, 'hypothesis_history'):
            if isinstance(mission.hypothesis_history, list):
                mission.hypothesis_history.append({
                    "hypothesis_id": str(hypothesis.id),
                    "old_status": old_status.value,
                    "new_status": new_status.value,
                    "reason": reason,
                    "confidence": hypothesis.confidence
                })

        logger.info(f"Hypothesis {hypothesis.id} transitioned from {old_status.value} to {new_status.value}. Reason: {reason}")
        return True

    def propose(self, hypothesis: Hypothesis, mission: Any = None) -> bool:
        return self.transition(hypothesis, HypothesisStatus.PROPOSED, "Proposed for review", mission)

    def review(self, hypothesis: Hypothesis, mission: Any = None) -> bool:
        return self.transition(hypothesis, HypothesisStatus.UNDER_REVIEW, "Moved to review", mission)

    def validate(self, hypothesis: Hypothesis, reason: str, mission: Any = None) -> bool:
        return self.transition(hypothesis, HypothesisStatus.VALIDATED, reason, mission)

    def reject(self, hypothesis: Hypothesis, reason: str, mission: Any = None) -> bool:
        return self.transition(hypothesis, HypothesisStatus.REJECTED, reason, mission)

    def archive(self, hypothesis: Hypothesis, reason: str, mission: Any = None) -> bool:
        return self.transition(hypothesis, HypothesisStatus.ARCHIVED, reason, mission)
