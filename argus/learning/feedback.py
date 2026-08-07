"""
Feedback Collector.

Receives and validates structured researcher feedback for investigations,
hypotheses, tasks and plugins.  All feedback is stored but NEVER used to
automatically modify execution plans or mission policy.
"""
import logging
from typing import Any, Dict, List, Optional

from argus.learning.models import (
    FeedbackEntry, FeedbackTag, FeedbackTargetType,
)
from argus.learning.registry import LearningRegistry

logger = logging.getLogger(__name__)


class FeedbackCollector:
    """
    Receives researcher feedback and persists it to the LearningRegistry.

    Validates that the target_id exists in the appropriate mission registry
    before storing.  Validation is best-effort — if the registry is
    unavailable the feedback is still recorded to avoid data loss.
    """

    def __init__(self, registry: LearningRegistry):
        self.registry = registry

    def submit(
        self,
        mission: Any,
        target_id: str,
        target_type: FeedbackTargetType,
        tag: FeedbackTag,
        comment: str = "",
        researcher: str = "unknown",
    ) -> FeedbackEntry:
        """
        Create and store a FeedbackEntry.

        Parameters
        ----------
        mission      : The active Mission object.
        target_id    : UUID string of the investigation, hypothesis or task.
        target_type  : FeedbackTargetType discriminator.
        tag          : Structured FeedbackTag label.
        comment      : Optional free-text comment.
        researcher   : Identifier of the submitting researcher.
        """
        mission_id = str(getattr(mission, "id", "unknown"))

        # Best-effort validation against the relevant mission registry
        self._validate_target(mission, target_id, target_type)

        entry = FeedbackEntry(
            mission_id=mission_id,
            target_id=target_id,
            target_type=target_type,
            tag=tag,
            comment=comment,
            researcher=researcher,
        )

        # Persist to global registry
        self.registry.add_feedback(entry)

        # Also append to mission.feedback list if available
        if hasattr(mission, "feedback") and isinstance(mission.feedback, list):
            mission.feedback.append(entry)

        logger.info(
            f"Feedback received: tag={tag.value} "
            f"on {target_type.value} {target_id} "
            f"(mission {mission_id})"
        )
        return entry

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _validate_target(
        self,
        mission: Any,
        target_id: str,
        target_type: FeedbackTargetType,
    ) -> None:
        """Log a warning when the target cannot be found (non-blocking)."""
        try:
            import uuid
            uid = uuid.UUID(target_id)

            if target_type == FeedbackTargetType.INVESTIGATION:
                reg = getattr(mission, "investigations", None)
                if reg and hasattr(reg, "find") and reg.find(uid) is None:
                    logger.warning(
                        f"Feedback: Investigation {target_id} not found in mission."
                    )

            elif target_type == FeedbackTargetType.HYPOTHESIS:
                reg = getattr(mission, "hypotheses", None)
                if reg and hasattr(reg, "find") and reg.find(uid) is None:
                    logger.warning(
                        f"Feedback: Hypothesis {target_id} not found in mission."
                    )

        except (ValueError, AttributeError):
            pass  # Non-UUID target_ids are allowed (e.g. plugin IDs)


class FeedbackSummarizer:
    """Aggregates and summarises feedback for a collection of FeedbackEntry objects."""

    @staticmethod
    def summarize(feedback_list: List[FeedbackEntry]) -> Dict[str, int]:
        """
        Count feedback by tag.

        Returns
        -------
        Dict mapping FeedbackTag.value → count.
        """
        counts: Dict[str, int] = {}
        for entry in feedback_list:
            key = entry.tag.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @staticmethod
    def useful_rate(feedback_list: List[FeedbackEntry]) -> float:
        """
        Fraction of feedback entries tagged as HIGH_VALUE or USEFUL_INVESTIGATION.
        Returns 0.0 when the list is empty.
        """
        if not feedback_list:
            return 0.0
        positive_tags = {FeedbackTag.HIGH_VALUE, FeedbackTag.USEFUL_INVESTIGATION}
        positive = sum(1 for e in feedback_list if e.tag in positive_tags)
        return positive / len(feedback_list)

    @staticmethod
    def false_positive_rate(feedback_list: List[FeedbackEntry]) -> float:
        """Fraction of feedback entries tagged as FALSE_POSITIVE."""
        if not feedback_list:
            return 0.0
        fp = sum(1 for e in feedback_list if e.tag == FeedbackTag.FALSE_POSITIVE)
        return fp / len(feedback_list)
