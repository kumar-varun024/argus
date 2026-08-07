"""
Learning Engine.

Central orchestrator for the Learning & Feedback Engine.

Responsibilities:
  1. Compute mission metrics after completion.
  2. Build and persist a LearningRecord.
  3. Discover patterns across historical records.
  4. Generate advisory recommendations for the planner.
  5. Store results in mission.learning, mission.metrics, mission.patterns.

Constraints (enforced in code):
  - Does NOT train or fine-tune AI models.
  - Does NOT modify execution plans automatically.
  - Does NOT alter mission policy.
  - Every recommendation carries requires_planner_approval = True.
  - Recommendations without a rationale are rejected before storage.
"""
import logging
from typing import Any, List, Optional

from argus.learning.feedback import FeedbackCollector, FeedbackSummarizer
from argus.learning.history import MissionHistoryStore
from argus.learning.metrics import MissionMetricsCalculator
from argus.learning.models import (
    DiscoveredPattern,
    LearningRecord,
    Recommendation,
)
from argus.learning.patterns import PatternDiscovery
from argus.learning.recommendations import RecommendationEngine
from argus.learning.registry import LearningRegistry, learning_registry

logger = logging.getLogger(__name__)


class LearningEngine:
    """
    Orchestrates feedback collection, metrics computation, pattern discovery,
    and recommendation generation for the Argus Learning & Feedback Engine.
    """

    def __init__(
        self,
        registry: Optional[LearningRegistry] = None,
        metrics_calculator: Optional[MissionMetricsCalculator] = None,
        pattern_discovery: Optional[PatternDiscovery] = None,
        recommendation_engine: Optional[RecommendationEngine] = None,
        history_store: Optional[MissionHistoryStore] = None,
        feedback_collector: Optional[FeedbackCollector] = None,
    ):
        self._registry = registry or learning_registry
        self._metrics = metrics_calculator or MissionMetricsCalculator()
        self._patterns = pattern_discovery or PatternDiscovery()
        self._recommendations = recommendation_engine or RecommendationEngine()
        self._history = history_store or MissionHistoryStore(self._registry)
        self._feedback = feedback_collector or FeedbackCollector(self._registry)

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def process_mission(self, mission: Any) -> LearningRecord:
        """
        Compute metrics, build a LearningRecord, persist it, and attach it to
        ``mission.learning``.

        Parameters
        ----------
        mission : A completed Mission object.

        Returns
        -------
        The created LearningRecord.
        """
        mission_id = str(getattr(mission, "id", "unknown"))
        logger.info(f"Learning: Processing mission {mission_id}")

        # 1. Calculate mission metrics
        metrics_record = self._metrics.calculate(mission)

        # 2. Temporarily expose metrics on mission.learning so MissionHistoryStore
        #    can include them in the LearningRecord.
        _sentinel = object()
        prev_learning = getattr(mission, "learning", _sentinel)

        class _Holder:
            def __init__(self, m):
                self.metrics = m

        if hasattr(mission, "learning"):
            mission.learning = _Holder(metrics_record)

        # 3. Extract full LearningRecord and persist
        record = self._history.record_mission(mission)
        record.metrics = metrics_record

        # 4. Store final record on mission.learning
        if hasattr(mission, "learning"):
            mission.learning = record

        # 5. Augment mission.metrics dict with learning summary
        self._write_metrics_to_mission(mission, metrics_record)

        # 6. Include per-mission feedback summary in metadata
        raw_feedback = getattr(mission, "feedback", []) or []
        if raw_feedback:
            summary = FeedbackSummarizer.summarize(raw_feedback)
            record.metadata["feedback_summary"] = summary

        logger.info(
            f"Learning: Mission {mission_id} processed — "
            f"coverage={metrics_record.coverage_pct:.0%}, "
            f"investigations={metrics_record.investigation_count}, "
            f"hypotheses={metrics_record.hypothesis_count}"
        )
        return record

    def discover_patterns(self) -> List[DiscoveredPattern]:
        """
        Run pattern detection across all historical LearningRecord objects.

        Returns an empty list when fewer than 2 records exist.
        """
        records = self._registry.get_all_records()
        patterns = self._patterns.discover(records)
        logger.info(f"Learning: {len(patterns)} pattern(s) discovered from {len(records)} record(s).")
        return patterns

    def generate_recommendations(
        self, mission: Any = None
    ) -> List[Recommendation]:
        """
        Discover patterns, then generate advisory recommendations.

        Parameters
        ----------
        mission : Optional Mission; if provided, recommendations are stored in
                  ``mission.patterns``.

        Returns
        -------
        Sorted list of Recommendation objects (High → Low priority).
        """
        patterns = self.discover_patterns()
        recommendations = self._recommendations.generate(patterns, mission)
        logger.info(f"Learning: {len(recommendations)} recommendation(s) generated.")
        return recommendations

    # ------------------------------------------------------------------
    # Feedback delegation
    # ------------------------------------------------------------------

    @property
    def feedback(self) -> FeedbackCollector:
        """Direct access to the FeedbackCollector."""
        return self._feedback

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _write_metrics_to_mission(self, mission: Any, metrics_record) -> None:
        """Augment mission.metrics dict with learning-derived values."""
        if not hasattr(mission, "metrics"):
            return
        if not isinstance(mission.metrics, dict):
            return
        mission.metrics["learning"] = {
            "coverage_pct": metrics_record.coverage_pct,
            "execution_time_seconds": metrics_record.execution_time_seconds,
            "investigation_count": metrics_record.investigation_count,
            "hypothesis_count": metrics_record.hypothesis_count,
            "validated_hypotheses": metrics_record.validated_hypotheses,
            "rejected_hypotheses": metrics_record.rejected_hypotheses,
            "evidence_quality": metrics_record.evidence_quality,
            "graph_completeness": metrics_record.graph_completeness,
            "task_completion_rate": metrics_record.task_completion_rate,
            "failed_task_count": metrics_record.failed_task_count,
        }


# Global singleton for convenience
learning_engine = LearningEngine()
